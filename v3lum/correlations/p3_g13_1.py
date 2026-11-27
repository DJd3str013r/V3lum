# Origin-IP hypothesis logic adapted from CloakQuest3r
# https://github.com/spyboy-productions/CloakQuest3r @ 2c6faf649170b194e12915c657d9c7ad8c7b6add
# MIT License, Copyright (c) 2023 Spyboy (notice: v3lum/data/notices/cloakquest3r.json)
# Cloudmare (AGPL-3.0) informed the design only; no Cloudmare code is used.
"""Correlation rules of batch p3-G13-1: CDN origin-IP hypotheses (P278) and SaaS tenant corroboration (P371).

``cdn_origin_hypothesis`` (P278) - final conditions and where they live:

1. A correlation rule over facts other modules already produced (:func:`domain_facts`): historical A
   records from SecurityTrails (P006 ``dns_history_a`` / ``origin_ip_candidates`` / ``historical_a_record``
   edges) and passive DNS (P015 ``passive_dns``), certificate SHA-256/SAN matches (CT ``has_certificate``,
   TLS ``handshake_certificate``, scan-engine ``cert_sha256`` / ``cert_sans`` / ``services`` / ``serves_certificate``
   edges), favicon mmh3 (P062) and page titles. No network call, no client import (disclosure 'none');
   SecurityTrails and Censys are never re-queried here.
2. CDN and cloud ranges are excluded through the shared interval indexes (:func:`range_label`): the AR06
   noise kind of the node (MISP warninglists of P169, ``cdn``/``cloud``/``hosting``/``saas``), the P034
   ``cloud_ranges`` attributes of the node, the bundled noise lists and the local P034 dataset copies
   (never a download). No subdomain brute force and no resolution: a history source that hit its quota or
   needs a key is a coverage note (:func:`history_coverage`), never a fallback.
3. Explicit weights (:data:`WEIGHTS`, cti_lead): a certificate fingerprint/SAN match on a non-CDN IP is
   strong; a pre-CDN historical A record is medium and decays with age (half-life
   :data:`HISTORY_HALF_LIFE_DAYS`); favicon or title matches are weak (phishing kits copy favicons) and
   capped at :data:`WEAK_CAP`; an IP hosting more than :data:`SHARED_IP_DOMAINS` domains is capped weak.
4. Output: one correlation per candidate (tag and relation ``origin_candidate``), title 'Possible origin
   (hypothesis) behind a CDN', the score, strength and evidence; the IP is never pivoted, expanded or
   used as a LIGHT/ACTIVE seed. Hostile sites (malicious/phishing/c2/suspicious tags) get an abuse aid:
   candidate hoster/ASN, its abuse contact and the fronting CDN's abuse form (tag ``abuse_aid``).
5. Nothing connects to a candidate (a Host-header verification would be ACTIVE and only for IPs listed in
   the scope file itself: docs/backlog/p3-G13-1.md).
6. Licences (A6): header above and the notice fragment; opt-in: the rule runs only with ``--preset deep``,
   ``--all-modules`` or ``-M cdn_origin_hypothesis`` (the offline module of that name,
   v3lum/modules/pentest_recon/cdn_origin_hypothesis.py). Synthetic graph fixtures:
   tests/fixtures/rules/cdn_origin_hypothesis/ (strong, medium, weak, hostile, quota and CDN-only cases).

``p3g131_saas_tenant_corroborated`` (P371 FC5): a tenant the module ``saas_tenant_discovery`` found under
the organisation's name stays a 'candidate tenant' until another fact corroborates it; after the scan this
rule looks for a P342 DNS verification record (``saas_vendors`` / ``txt``) or P011 identity-provider
metadata (``identity_provider`` edges, ``m365_identity_provider``) on the organisation's domains and emits
'SaaS tenant corroborated'. A homonym is never attributed by name alone: no corroboration, no correlation.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from v3lum.core import noise
from v3lum.core.correlate import rule
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph, Node
from v3lum.core.models import Correlation, Severity

RULE_ORIGIN = "cdn_origin_hypothesis"
RULE_TENANT = "p3g131_saas_tenant_corroborated"
#: the offline opt-in module (``-M cdn_origin_hypothesis``)
MODULE_NAME = "cdn_origin_hypothesis"
TENANT_MODULE = "saas_tenant_discovery"
LABEL = "possible origin (hypothesis)"
ORIGIN_TITLE = "Possible origin (hypothesis) behind a CDN"
TENANT_TITLE = "SaaS tenant corroborated for the organisation"

#: P278 FC3 weights (cti_lead's ordering made numeric). Noisy-OR combination, one item per kind.
WEIGHTS: dict[str, float] = {
    "cert_fingerprint": 0.60,  # strong: same certificate (SHA-256) on a non-CDN IP
    "cert_san": 0.50,  # strong: a certificate naming the domain on a non-CDN IP
    "historical_a_pre_cdn": 0.35,  # medium: A record before the CDN era, decays with age
    "historical_a_during_cdn": 0.25,  # medium-low: non-CDN A seen during the CDN era (leak or provider switch), decays
    "historical_a_undated": 0.20,  # medium-low: historical A without dates (cannot be placed before the CDN)
    "favicon_mmh3": 0.08,  # weak: phishing kits copy favicons
    "title": 0.08,  # weak
}
HISTORY_HALF_LIFE_DAYS = 1095  # three years
HISTORY_FLOOR = 0.05
WEAK_CAP = 0.15  # favicon/title-only evidence and shared IPs never exceed this
SHARED_IP_DOMAINS = 50
BANDS: tuple[tuple[str, float], ...] = (("strong", 0.50), ("medium", 0.20), ("weak", 0.0))
CDN_ERA_GAP_DAYS = 30
EXCLUDE_KINDS: tuple[str, ...] = ("cdn", "cloud")  # FC2: CDN and cloud ranges
CDN_KINDS: tuple[str, ...] = ("cdn",)
MAX_SEEDS = 25
MAX_CANDIDATES = 10
MAX_IP_NODES = 5000
_WEAK_KINDS = frozenset({"favicon_mmh3", "title"})
_HISTORY_KINDS = frozenset({"historical_a_pre_cdn", "historical_a_during_cdn", "historical_a_undated"})
HOSTILE_TAGS = frozenset({"malicious", "phishing", "c2", "suspicious", "hostile", "malware"})
#: CDN abuse-report forms (P278 FC4). Only Cloudflare's was verified to exist (2026-11-26; it answers
#: 'Sorry, you have been blocked' to the datacenter egress: a manual link for the analyst's browser, never fetched).
CDN_ABUSE_FORMS: dict[str, str] = {"cloudflare": "https://abuse.cloudflare.com/"}
HISTORY_MODULES = frozenset({"securitytrails", "passive_dns", "virustotal", "hackertarget", "whois_history_keyed"})
SITE_CERT_RELATIONS = frozenset({"has_certificate", "handshake_certificate"})
REFERENCES = ("https://github.com/spyboy-productions/CloakQuest3r", "https://attack.mitre.org/techniques/T1590/")

_NON_ROUTABLE = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
))
_GENERIC_TITLES = frozenset({
    "", "index of /", "welcome to nginx!", "403 forbidden", "404 not found", "just a moment...", "home", "attention required! | cloudflare",
    "iis windows server", "apache2 ubuntu default page: it works", "test page for the apache http server", "default web site page", "error",
    "access denied", "login", "302 found", "301 moved permanently", "502 bad gateway", "503 service unavailable", "web server's default page",
})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# ======================================================================================
# Pure helpers (never raise on junk)
# ======================================================================================


def parse_day(value: Any) -> _dt.date | None:
    """'2024-02-28' | '2024-02-28T10:00:00Z' | epoch seconds/millis | date/datetime -> UTC date, or None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value.astimezone(_dt.timezone.utc).date() if value.tzinfo else value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000.0 if float(value) > 1e11 else float(value)
        if not 0 < seconds < 4.2e9:
            return None
        return _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc).date()
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return parse_day(int(text))
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
        if m:
            try:
                return _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return None
    return None


def _ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        addr = ipaddress.ip_address(value.strip().strip("[]").rstrip("."))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def is_routable_candidate(ip: str) -> bool:
    """Private, loopback, CGNAT, link-local, multicast and reserved addresses (parking and sinkhole values common in
    passive DNS) are never origin candidates. Documentation ranges stay (synthetic fixtures use them)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr.version == net.version and addr in net for net in _NON_ROUTABLE)


def history_records(items: Any, source: str | None = None, *, name: str = "") -> list[dict[str, Any]]:
    """Historical A/AAAA facts -> ``[{ip, first_seen, last_seen, source}]`` (dates as ``date`` or None).

    Accepts P006 ``dns_history_a`` / ``origin_ip_candidates`` records ``{ip, first_seen, last_seen}``, raw
    SecurityTrails records ``{values: [{ip}], first_seen, last_seen}`` (every value: not CloakQuest3r's
    ``values[0]``), P015 ``passive_dns`` rows ``{hostname, address, record_type, first_seen, last_seen}`` (only
    rows for ``name`` when given), COF/Robtex ``{rrtype, rdata|rrdata, time_first, time_last}`` and mnemonic
    ``{rrtype, answer, firstSeenTimestamp, lastSeenTimestamp}``. Non-A/AAAA rows and bad addresses are dropped."""
    if isinstance(items, Mapping):
        items = items.get("records") if isinstance(items.get("records"), list) else [items]
    if not isinstance(items, (list, tuple)):
        return []
    want = name.strip().lower().rstrip(".")
    out: list[dict[str, Any]] = []
    for rec in items:
        if not isinstance(rec, Mapping):
            continue
        rtype = next((rec.get(k) for k in ("record_type", "rrtype", "type") if isinstance(rec.get(k), str)), None)
        if rtype is not None and rtype.strip().lower() not in ("a", "aaaa", "a/ipv4", "aaaa/ipv6"):
            continue
        host = next((rec.get(k) for k in ("hostname", "rrname") if isinstance(rec.get(k), str)), None)
        if want and host is not None and host.strip().lower().rstrip(".") != want:
            continue
        first = next((d for d in (parse_day(rec.get(k)) for k in ("first_seen", "time_first", "firstSeenTimestamp", "first_seen_epoch")) if d), None)
        last = next((d for d in (parse_day(rec.get(k)) for k in ("last_seen", "time_last", "lastSeenTimestamp", "last_seen_epoch")) if d), None)
        values: list[Any] = []
        if isinstance(rec.get("values"), list):
            values = [v.get("ip") for v in rec["values"] if isinstance(v, Mapping)]
        else:
            for key in ("ip", "address", "rdata", "rrdata", "answer"):
                v = rec.get(key)
                if isinstance(v, list):
                    values.extend(v)
                    break
                if v is not None:
                    values.append(v)
                    break
        src = rec.get("source") if isinstance(rec.get("source"), str) else source
        for value in values:
            ip = _ip(value)
            if ip:
                out.append({"ip": ip, "first_seen": first, "last_seen": last, "source": src or "unknown"})
    return out


def san_covers(san: Any, host: str) -> bool:
    """A certificate name covers ``host``: exact, or a single-label wildcard ('*.example.com' covers www.example.com,
    not example.com or a.b.example.com)."""
    if not isinstance(san, str) or not isinstance(host, str):
        return False
    s, h = san.strip().lower().rstrip("."), host.strip().lower().rstrip(".")
    if not s or not h:
        return False
    if s == h:
        return True
    return s.startswith("*.") and h.count(".") >= 2 and h.split(".", 1)[1] == s[2:]


def normalise_title(title: Any) -> str | None:
    """A page title in comparable form, or None for generic/default titles (never a match signal)."""
    if not isinstance(title, str):
        return None
    text = " ".join(unicodedata.normalize("NFKC", title).split()).strip().lower()
    if text in _GENERIC_TITLES or len(text) < 4:
        return None
    return text[:200]


def evidence_weight(kind: str, *, last_seen: _dt.date | None = None, as_of: _dt.date | None = None) -> float:
    """Weight of one evidence item; historical A evidence decays (half-life three years, floor 0.05)."""
    weight = WEIGHTS.get(kind, 0.0)
    if kind in ("historical_a_pre_cdn", "historical_a_during_cdn") and last_seen and as_of:
        age = max(0, (as_of - last_seen).days)
        weight = max(HISTORY_FLOOR, weight * 0.5 ** (age / HISTORY_HALF_LIFE_DAYS))
    return round(weight, 4)


def combine_score(weights: Iterable[float]) -> float:
    rest = 1.0
    for w in weights:
        rest *= 1.0 - max(0.0, min(1.0, float(w)))
    return round(1.0 - rest, 4)


def strength_of(score: float) -> str:
    for name, low in BANDS:
        if score >= low and (name != "weak" or score > 0):
            return name
    return "none"


def history_coverage(statuses: Any) -> list[dict[str, str]]:
    """``{source: status}`` -> coverage notes for history sources that did not answer (quota, needs_key, licence,
    rate_limited, blocked...): shown, never replaced by brute force or active resolution (P278 FC2)."""
    out: list[dict[str, str]] = []
    if not isinstance(statuses, Mapping):
        return out
    for src, st in sorted(statuses.items()):
        if not isinstance(st, str) or st in ("ok", "empty", "cached"):
            continue
        out.append({"source": str(src), "status": st,
                    "note": f"history from {src} unavailable ({st}): no fallback to brute force or active resolution"})
    return out


def cdn_front(current: Iterable[str], labeller: Callable[[str], Mapping[str, Any] | None]) -> dict[str, Any]:
    """Is the domain fronted by a CDN now? Every current address must be in a CDN range (the passive replacement
    for CloakQuest3r's active CDN check). -> {fronted, providers, current, non_cdn_current}"""
    ips = [ip for ip in dict.fromkeys(_ip(x) for x in current) if ip]
    providers: list[str] = []
    non_cdn: list[str] = []
    for ip in ips:
        lab = labeller(ip)
        if lab and lab.get("kind") in CDN_KINDS:
            prov = str(lab.get("provider") or "CDN")
            if prov not in providers:
                providers.append(prov)
        else:
            non_cdn.append(ip)
    return {"fronted": bool(ips) and not non_cdn, "providers": providers, "current": ips, "non_cdn_current": non_cdn}


def cdn_era_start(history: list[dict[str, Any]], labeller: Callable[[str], Mapping[str, Any] | None]) -> _dt.date | None:
    """First day of the current contiguous CDN era from history (gaps up to CDN_ERA_GAP_DAYS joined)."""
    cdn = [r for r in history if r.get("first_seen") and (labeller(r["ip"]) or {}).get("kind") in CDN_KINDS]
    if not cdn:
        return None
    cdn.sort(key=lambda r: (r.get("last_seen") or r["first_seen"], r["first_seen"]), reverse=True)
    start = cdn[0]["first_seen"]
    changed = True
    while changed:
        changed = False
        for r in cdn:
            last = r.get("last_seen") or r["first_seen"]
            if r["first_seen"] < start and last >= start - _dt.timedelta(days=CDN_ERA_GAP_DAYS):
                start = r["first_seen"]
                changed = True
    return start


def abuse_aid(candidate: Mapping[str, Any], fronting: Iterable[str]) -> dict[str, Any]:
    """Abuse-reporting aid for a hostile site (P278 FC4): candidate hoster/ASN, its abuse contact and the fronting
    CDN's abuse form. Manual follow-up only: nothing is contacted."""
    forms = []
    for prov in fronting or ():
        key = next((k for k in CDN_ABUSE_FORMS if k in str(prov or "").lower()), None)
        forms.append({"provider": str(prov), "abuse_form": CDN_ABUSE_FORMS.get(key) if key else None})
    email = candidate.get("abuse_email")
    return {
        "candidate_ip": candidate.get("value"),
        "asn": candidate.get("asn"),
        "hoster": candidate.get("as_name"),
        "hoster_abuse_contact": email if isinstance(email, str) and "@" in email else None,
        "cdn_abuse_forms": forms,
        "note": "hypothesis: report to the CDN first; the candidate hoster is unconfirmed",
    }


def origin_hypotheses(facts: Mapping[str, Any], labeller: Callable[[str], Mapping[str, Any] | None], *, as_of: Any = None,
                      exclude_kinds: Iterable[str] = EXCLUDE_KINDS) -> dict[str, Any]:
    """The P278 rule as a pure function: facts other modules produced -> scored origin candidates.

    ``facts`` = {seed, current_a [ip], history_a [records], history_status {source: status}, site {cert_sha256 [],
    favicon_mmh3, title}, ip_observations [{ip, source, cert_sha256 [], cert_sans [], favicon_mmh3 [], title [],
    hosted_domain_count, shared, asn, as_name, abuse_email}], default_favicons [int], hostile bool}."""
    facts = facts if isinstance(facts, Mapping) else {}
    seed = str(facts.get("seed") or "").strip().lower().rstrip(".")
    as_of_d = parse_day(as_of) or parse_day(facts.get("as_of")) or _dt.datetime.now(_dt.timezone.utc).date()
    excluded_kinds = set(exclude_kinds)
    result: dict[str, Any] = {"seed": seed, "applicable": False, "reason": None, "fronted_by": [], "cdn_since": None, "candidates": [],
                              "excluded": [], "coverage": history_coverage(facts.get("history_status")), "disclosure": "none",
                              "network_requests": 0}
    if not seed:
        result["reason"] = "no_seed_domain"
        return result
    front = cdn_front(facts.get("current_a") or [], labeller)
    result["fronted_by"] = front["providers"]
    if not front["current"]:
        result["reason"] = "no_current_resolution"
        return result
    if not front["fronted"]:
        result["reason"] = "not_cdn_fronted"  # origin exposed directly or a mixed answer: nothing to hypothesise
        return result
    result["applicable"] = True
    history = history_records(facts.get("history_a") or [])
    era = cdn_era_start(history, labeller)
    result["cdn_since"] = era.isoformat() if era else None
    current = set(front["current"])
    slots: dict[str, dict[str, Any]] = {}
    seen_excluded: set[str] = set()

    def slot(ip: str) -> dict[str, Any] | None:
        if ip in current:
            return None
        if ip in slots:
            return slots[ip]
        if not is_routable_candidate(ip):
            if ip not in seen_excluded:
                seen_excluded.add(ip)
                result["excluded"].append({"ip": ip, "why": "non-routable address"})
            return None
        lab = labeller(ip)
        if lab and lab.get("kind") in excluded_kinds:
            if ip not in seen_excluded:
                seen_excluded.add(ip)
                result["excluded"].append({"ip": ip, "why": f"{lab.get('kind')} range: {lab.get('label') or lab.get('provider') or ''}".strip()})
            return None
        slots[ip] = {"ip": ip, "evidence": [], "range": dict(lab) if lab else None, "hosted_domain_count": None, "shared": False,
                     "asn": None, "as_name": None, "abuse_email": None}
        return slots[ip]

    for rec in history:
        cand = slot(rec["ip"])
        if cand is None:
            continue
        last = rec.get("last_seen")
        if last is None:
            kind = "historical_a_undated"
        elif era is None or last <= era + _dt.timedelta(days=CDN_ERA_GAP_DAYS):
            kind = "historical_a_pre_cdn"
        else:
            kind = "historical_a_during_cdn"
        cand["evidence"].append({"kind": kind, "source": rec.get("source"),
                                 "first_seen": rec["first_seen"].isoformat() if rec.get("first_seen") else None,
                                 "last_seen": last.isoformat() if last else None,
                                 "weight": evidence_weight(kind, last_seen=last, as_of=as_of_d)})

    site = facts.get("site") if isinstance(facts.get("site"), Mapping) else {}
    site_fps = {str(x).strip().lower().replace(":", "") for x in site.get("cert_sha256") or [] if isinstance(x, str)}
    site_fps = {x for x in site_fps if _SHA256_RE.match(x)}
    defaults = {x for x in facts.get("default_favicons") or [] if isinstance(x, int) and not isinstance(x, bool)}
    site_favs = {x for x in site.get("favicon_mmh3") or [] if isinstance(x, int) and not isinstance(x, bool) and x not in defaults}
    site_titles = {t for t in (normalise_title(x) for x in site.get("title") or []) if t}

    for obs in facts.get("ip_observations") or []:
        if not isinstance(obs, Mapping):
            continue
        ip = _ip(obs.get("ip"))
        cand = slot(ip) if ip else None
        if cand is None:
            continue
        src = obs.get("source") or "graph"
        fps = {str(x).strip().lower().replace(":", "") for x in obs.get("cert_sha256") or [] if isinstance(x, str)}
        match_fp = sorted(fps & site_fps)
        if match_fp:
            cand["evidence"].append({"kind": "cert_fingerprint", "source": src, "detail": match_fp[0], "weight": evidence_weight("cert_fingerprint")})
        sans = [s for s in obs.get("cert_sans") or [] if san_covers(s, seed)]
        if sans:
            cand["evidence"].append({"kind": "cert_san", "source": src, "detail": sans[0], "weight": evidence_weight("cert_san")})
        favs = {x for x in obs.get("favicon_mmh3") or [] if isinstance(x, int) and not isinstance(x, bool)} & site_favs
        if favs:
            cand["evidence"].append({"kind": "favicon_mmh3", "source": src, "detail": str(sorted(favs)[0]), "weight": evidence_weight("favicon_mmh3")})
        titles = {t for t in (normalise_title(x) for x in obs.get("title") or []) if t} & site_titles
        if titles:
            cand["evidence"].append({"kind": "title", "source": src, "detail": sorted(titles)[0], "weight": evidence_weight("title")})
        count = obs.get("hosted_domain_count")
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
            cand["hosted_domain_count"] = max(count, cand["hosted_domain_count"] or 0)
        cand["shared"] = cand["shared"] or obs.get("shared") is True
        for key in ("asn", "as_name", "abuse_email"):
            if obs.get(key) not in (None, "") and cand[key] is None:
                cand[key] = obs.get(key)

    hostile = bool(facts.get("hostile"))
    out = []
    for cand in slots.values():
        if not cand["evidence"]:
            continue
        best: dict[str, dict[str, Any]] = {}
        for ev in cand["evidence"]:  # one item per kind (the strongest): the same fact from several sources never inflates
            if ev["kind"] not in best or ev["weight"] > best[ev["kind"]]["weight"]:
                best[ev["kind"]] = ev
        if len(best.keys() & _HISTORY_KINDS) > 1:  # one history item: the strongest placement wins
            keep = max((best[k] for k in best.keys() & _HISTORY_KINDS), key=lambda e: e["weight"])
            best = {k: v for k, v in best.items() if k not in _HISTORY_KINDS or v is keep}
        score = combine_score(e["weight"] for e in best.values())
        caps: list[str] = []
        if set(best) <= _WEAK_KINDS:
            score = min(score, WEAK_CAP)
            caps.append("favicon/title only: weak (phishing kits copy favicons and titles)")
        if (cand["hosted_domain_count"] or 0) > SHARED_IP_DOMAINS or cand["shared"]:
            score = min(score, WEAK_CAP)
            caps.append(f"shared IP (more than {SHARED_IP_DOMAINS} domains): weak")
        row = {"type": "ipv6" if ":" in cand["ip"] else "ipv4", "value": cand["ip"], "relation": "origin_candidate", "label": LABEL,
               "score": score, "strength": strength_of(score), "expand": False, "seed_eligible": False,
               "evidence": sorted(best.values(), key=lambda e: (-e["weight"], e["kind"])), "caps": caps,
               "hosted_domain_count": cand["hosted_domain_count"], "asn": cand["asn"], "as_name": cand["as_name"], "range": cand["range"]}
        if hostile:
            row["abuse_aid"] = abuse_aid({**row, "abuse_email": cand["abuse_email"]}, front["providers"])
        out.append(row)
    out.sort(key=lambda r: (-r["score"], r["value"]))
    result["candidates"] = out
    return result


# ======================================================================================
# Graph adapters (read-only)
# ======================================================================================


def _nodes(graph: Any) -> list[Node]:
    nodes = getattr(graph, "nodes", None)
    return list(nodes.values()) if isinstance(nodes, dict) else []


def _edges(graph: Any) -> list[Any]:
    edges = getattr(graph, "edges", None)
    return list(edges) if isinstance(edges, list) else []


def _attr(node: Any, name: str) -> list[Any]:
    try:
        return list(node.attr_values(name))
    except Exception:  # noqa: BLE001 - a malformed node never breaks the rule
        return []


def adjacency(graph: Any) -> dict[str, list[Any]]:
    """node key -> the edges touching it (built once per rule run: no per-node scan of every edge)."""
    adj: dict[str, list[Any]] = {}
    for edge in _edges(graph):
        adj.setdefault(str(edge.src), []).append(edge)
        if edge.dst != edge.src:
            adj.setdefault(str(edge.dst), []).append(edge)
    return adj


def _out(adj: Mapping[str, list[Any]], key: str, relations: Iterable[str] | None = None) -> list[Any]:
    wanted = set(relations) if relations is not None else None
    return [e for e in adj.get(key, ()) if e.src == key and (wanted is None or e.relation in wanted)]


def _key_value(key: str) -> tuple[str, str]:
    etype, _, value = str(key).partition(":")
    return etype, value


def _ints(values: Iterable[Any]) -> list[int]:
    out: list[int] = []
    for v in values:
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            out.append(v)
        elif isinstance(v, str) and re.fullmatch(r"-?\d{1,11}", v.strip()):
            out.append(int(v.strip()))
    return out


def _local_classification(ip: str) -> Mapping[str, Any] | None:
    """P034 local dataset copies (never a download, never a network call); None when absent."""
    try:
        from v3lum.modules.ip_network import cloud_ranges
    except ImportError:  # pragma: no cover - the module ships with the core tree
        return None
    try:
        found = cloud_ranges.local_classification(ip)
    except Exception:  # noqa: BLE001 - a broken local copy never makes an address CDN
        return None
    return found if isinstance(found, Mapping) else None


def range_label(graph: Any, ip: str) -> dict[str, Any] | None:
    """{kind 'cdn' | 'cloud', provider, label, source} of an address from the shared indexes, or None."""
    ent = Entity.try_make(T.IPV6 if ":" in ip else T.IPV4, ip)
    if ent is None:
        return None
    node = graph.get(ent) if hasattr(graph, "get") else None
    if node is not None:
        role = str(node.attr("cloud_role") or "")
        provider = str(node.attr("cloud_provider") or "")
        label = str(node.attr("cloud_label") or "")
        if node.attr("is_cdn") is True or role == "cdn_edge":
            return {"kind": "cdn", "provider": provider or "CDN", "label": label or "CDN edge", "source": "cloud_ranges"}
        if node.attr("is_cloud") is True or role:
            return {"kind": "cloud", "provider": provider or "cloud", "label": label or role or "cloud range", "source": "cloud_ranges"}
        kind = str(getattr(node, "noise_kind", "") or "")
        if kind == "cdn":
            return {"kind": "cdn", "provider": provider or "CDN", "label": "CDN range (noise list)", "source": "noise"}
        if kind in ("cloud", "hosting", "saas"):
            return {"kind": "cloud", "provider": provider or kind, "label": f"{kind} range (noise list)", "source": "noise"}
    try:
        kinds = noise.noise_kinds(ent)
    except Exception:  # noqa: BLE001
        kinds = frozenset()
    if "cdn" in kinds:
        return {"kind": "cdn", "provider": "CDN", "label": "CDN range (noise list)", "source": "noise"}
    if kinds & {"cloud", "hosting", "saas"}:
        return {"kind": "cloud", "provider": "cloud", "label": "shared cloud/hosting range (noise list)", "source": "noise"}
    cls = _local_classification(ip)
    if cls:
        kind = "cdn" if cls.get("is_cdn") else "cloud"
        return {"kind": kind, "provider": str(cls.get("provider") or kind), "label": str(cls.get("label") or ""), "source": "cloud_ranges"}
    return None


def _site_nodes(graph: Any, node: Node) -> list[Node]:
    """The domain node plus its root URL nodes (https://<domain>/, http://<domain>/)."""
    out = [node]
    host = str(node.entity.value)
    for scheme in ("https", "http"):
        for suffix in ("/", ""):
            url = graph.get(f"url:{scheme}://{host}{suffix}") if hasattr(graph, "get") else None
            if url is not None and url not in out:
                out.append(url)
    return out


def _neighbours(adj: Mapping[str, list[Any]], key: str, etype: str) -> list[str]:
    vals: list[str] = []
    for edge in adj.get(key, ()):
        other = edge.dst if edge.src == key else edge.src
        t, v = _key_value(other)
        if t == etype and v not in vals:
            vals.append(v)
    return vals


def _service_values(node: Node, field: str) -> list[Any]:
    return [s.get(field) for s in _attr(node, "services") if isinstance(s, Mapping) and s.get(field) not in (None, "")]


def _default_favicons() -> set[int]:
    try:
        from v3lum.modules.url_web import favicon as fav
    except ImportError:  # pragma: no cover
        return set()
    try:
        defaults = fav.load_favicon_defaults()
    except Exception:  # noqa: BLE001
        return set()
    return {int(k) for k, v in defaults.items() if isinstance(v, Mapping) and v.get("noise", True)}


def _hosted_count(adj: Mapping[str, list[Any]], node: Node) -> tuple[int | None, bool]:
    count: int | None = None
    shared = False
    for value in _attr(node, "cohosting"):
        if isinstance(value, Mapping):
            c = value.get("count")
            if isinstance(c, int) and not isinstance(c, bool):
                count = max(count or 0, c)
            shared = shared or value.get("exclude_from_shared_infra") is True and bool(value.get("reason"))
    if any(v is True for v in _attr(node, "shared_ip")):
        shared = True
    hosted = {e.dst for e in _out(adj, node.key, ("hosted_domain",))}
    if hosted:
        count = max(count or 0, len(hosted))
    return count, shared


def _ip_observation(adj: Mapping[str, list[Any]], node: Node) -> dict[str, Any]:
    fps = [str(v) for v in _attr(node, "cert_sha256") if isinstance(v, str)]
    fps += [str(v) for v in _service_values(node, "cert_sha256")]
    fps += [str(v.get("sha256")) for v in _attr(node, "tls_certificate") if isinstance(v, Mapping) and v.get("sha256")]
    fps += _neighbours(adj, node.key, T.CERT_FP.value)
    sans = [str(v) for v in _attr(node, "cert_sans") if isinstance(v, str)]
    sans += [e.dst.partition(":")[2] for e in _out(adj, node.key, ("cert_san",))]
    favs = _ints(_attr(node, "favicon_mmh3")) + _ints(_service_values(node, "favicon_hash"))
    favs += _ints(_neighbours(adj, node.key, "favicon_hash"))
    titles = [str(v) for v in _attr(node, "title") if isinstance(v, str)] + [str(v) for v in _service_values(node, "http_title")]
    count, shared = _hosted_count(adj, node)
    abuse = next((v for v in _attr(node, "abuse_contact") if isinstance(v, str) and "@" in v), None)
    if abuse is None:
        abuse = next((v.get("email") for v in _attr(node, "abuse_contacts") if isinstance(v, Mapping) and isinstance(v.get("email"), str)), None)
    sources = sorted({s for s in getattr(node, "sources", set()) or set() if isinstance(s, str)})
    return {
        "ip": node.entity.value, "source": ", ".join(sources[:3]) or "graph", "cert_sha256": fps, "cert_sans": sans, "favicon_mmh3": favs,
        "title": titles, "hosted_domain_count": count, "shared": shared, "asn": node.attr("asn"), "as_name": node.attr("as_org"),
        "abuse_email": abuse,
    }


def _status_of(result: Any) -> str:
    status = getattr(result, "status", None)
    value = str(getattr(status, "value", status) or "")
    code = str(getattr(result, "reason_code", "") or "")
    if value == "skipped" and code:
        return code
    return value


def ip_observations(graph: Any, adj: Mapping[str, list[Any]] | None = None) -> list[dict[str, Any]]:
    """Scan-engine/pDNS facts of every IP node of the graph (at most MAX_IP_NODES)."""
    adj = adjacency(graph) if adj is None else adj
    ips = [n for n in _nodes(graph) if n.entity.type in (T.IPV4, T.IPV6)][:MAX_IP_NODES]
    return [_ip_observation(adj, n) for n in ips]


def domain_facts(graph: Graph, node: Node, results: Iterable[Any], now: Any, *, adj: Mapping[str, list[Any]] | None = None,
                 observations: list[dict[str, Any]] | None = None, default_favicons: Iterable[int] | None = None) -> dict[str, Any]:
    """The P278 facts of one domain node, read from the graph and the results (never a request)."""
    adj = adjacency(graph) if adj is None else adj
    seed = str(node.entity.value)
    current = [v for v in _attr(node, "a_records") + _attr(node, "aaaa_records") if isinstance(v, str)]
    if not current:
        current = [e.dst.partition(":")[2] for e in _out(adj, node.key, ("resolves_to",)) if e.module == "dns_records"]
    history: list[dict[str, Any]] = []
    history += history_records([v for v in _attr(node, "dns_history_a") if isinstance(v, Mapping)], "securitytrails")
    history += history_records([v for v in _attr(node, "origin_ip_candidates") if isinstance(v, Mapping)], "securitytrails")
    history += history_records([v for v in _attr(node, "passive_dns") if isinstance(v, Mapping)], "passive_dns", name=seed)
    dated = {r["ip"] for r in history}
    for edge in _out(adj, node.key, ("historical_a_record",)):
        ip = _ip(edge.dst.partition(":")[2])
        if ip and ip not in dated:
            history.append({"ip": ip, "first_seen": None, "last_seen": None, "source": edge.module or "graph"})
    statuses: dict[str, str] = {}
    for res in results or ():
        ent = getattr(res, "entity", None)
        if getattr(res, "module", "") in HISTORY_MODULES and getattr(ent, "key", None) == node.key:
            statuses[str(res.module)] = _status_of(res)
    site_fps: list[str] = []
    site_favs: list[int] = []
    site_titles: list[str] = []
    for site in _site_nodes(graph, node):
        site_fps += [str(v) for v in _attr(site, "cert_sha256") if isinstance(v, str)]
        site_fps += [str(v.get("sha256")) for v in _attr(site, "tls_certificate") if isinstance(v, Mapping) and v.get("sha256")]
        site_fps += [e.dst.partition(":")[2] for e in _out(adj, site.key, SITE_CERT_RELATIONS)]
        noisy = bool(_attr(site, "favicon_noise"))
        if not noisy:
            site_favs += _ints(_attr(site, "favicon_mmh3"))
            site_favs += _ints(v.get("mmh3") for v in _attr(site, "favicon") if isinstance(v, Mapping))
        site_titles += [str(v) for v in _attr(site, "title") if isinstance(v, str)]
    if observations is None:
        observations = ip_observations(graph, adj)
    hostile = bool(node.tagged(*HOSTILE_TAGS)) if hasattr(node, "tagged") else False
    return {
        "seed": seed, "as_of": parse_day(now), "current_a": current, "history_a": history, "history_status": statuses,
        "site": {"cert_sha256": site_fps, "favicon_mmh3": site_favs, "title": site_titles}, "ip_observations": observations,
        "default_favicons": sorted(_default_favicons() if default_favicons is None else set(default_favicons)), "hostile": hostile,
    }


def _opted_in(rctx: Any, results: Iterable[Any]) -> bool:
    """P278 FC6: opt-in only (--preset deep, --all-modules or -M cdn_origin_hypothesis)."""
    opts = getattr(rctx, "options", None)
    if opts is not None:
        if str(getattr(opts, "preset", "") or "").lower() == "deep" or bool(getattr(opts, "include_disabled", False)):
            return True
        if MODULE_NAME in set(getattr(opts, "include", None) or ()):
            return True
    return any(getattr(r, "module", "") == MODULE_NAME for r in results or ())


_KIND_WORDS = {
    "cert_fingerprint": "same certificate SHA-256 as the site",
    "cert_san": "a certificate naming the domain",
    "historical_a_pre_cdn": "A record from before the CDN era",
    "historical_a_during_cdn": "non-CDN A record seen during the CDN era",
    "historical_a_undated": "historical A record (dates unknown)",
    "favicon_mmh3": "same favicon hash as the site",
    "title": "same page title as the site",
}


def _evidence_line(ev: Mapping[str, Any]) -> str:
    text = f"{ev['kind']} ({_KIND_WORDS.get(ev['kind'], ev['kind'])}): weight {ev['weight']}"
    if ev.get("first_seen") or ev.get("last_seen"):
        text += f", seen {ev.get('first_seen') or '?'} .. {ev.get('last_seen') or '?'}"
    if ev.get("detail"):
        text += f", {str(ev['detail'])[:80]}"
    return text + f" [{ev.get('source') or 'graph'}]"


# ======================================================================================
# Rules
# ======================================================================================


@rule(
    RULE_ORIGIN,
    ORIGIN_TITLE,
    "P278: possible origin IPs of a CDN-fronted domain from facts already collected (historical A records, certificate, "
    "favicon and title matches on non-CDN addresses); a scored hypothesis, never contacted, never a seed. Opt-in.",
    version="1",
    severity="info",
    criterion="every current address of the domain is in a CDN range and a non-CDN address carries origin evidence "
              "(certificate fingerprint/SAN = strong, pre-CDN historical A = medium decaying, favicon/title = weak; P278 FC3)",
    references=REFERENCES,
    attack=("T1590",),
    false_positives="Reassigned cloud/hosting addresses, old origins, shared hosts and copied favicons/titles (phishing kits): "
                    "hypotheses only, weak signals capped.",
)
def cdn_origin_hypothesis(graph: Graph, results: list[Any], rctx: Any) -> list[Correlation]:
    if not _opted_in(rctx, results):
        return []
    now = getattr(rctx, "now", None)
    out: list[Correlation] = []
    seeds = [n for n in _nodes(graph) if n.entity.type is T.DOMAIN and n.seed][:MAX_SEEDS]
    if not seeds:
        return []
    adj = adjacency(graph)
    observations = ip_observations(graph, adj)
    defaults = _default_favicons()
    for node in seeds:
        facts = domain_facts(graph, node, results, now, adj=adj, observations=observations, default_favicons=defaults)
        result = origin_hypotheses(facts, lambda ip: range_label(graph, ip), as_of=now)
        if not result["applicable"]:
            continue
        fronted = ", ".join(result["fronted_by"]) or "a CDN"
        coverage = [c["note"] for c in result["coverage"]]
        for cand in result["candidates"][:MAX_CANDIDATES]:
            ent = Entity.try_make(T.IPV6 if cand["type"] == "ipv6" else T.IPV4, cand["value"])
            if ent is None:
                continue
            kinds = [e["kind"] for e in cand["evidence"]]
            own = getattr(node, "ownership", "") == "own_asset"
            severity = Severity.LOW if cand["strength"] == "strong" and own else Severity.INFO
            evidence = [_evidence_line(e) for e in cand["evidence"]] + cand["caps"]
            if cand.get("range"):
                evidence.append(f"range: {cand['range'].get('label') or cand['range'].get('provider')} (not a CDN edge)")
            if cand.get("asn") or cand.get("as_name"):
                evidence.append(f"hoster: {cand.get('as_name') or '?'} ({cand.get('asn') or '?'})")
            evidence += coverage
            if result["excluded"]:
                evidence.append(f"excluded: {len(result['excluded'])} address(es) on CDN/cloud or non-routable ranges")
            tags = ["origin_candidate", "hypothesis", "cdn_origin_hypothesis"]
            references: list[str] = []
            recommendation = ("Treat as a hypothesis: confirm passively (scan-engine data showing the site's certificate on the address). "
                              "A Host-header check against the address is ACTIVE and only for IPs listed in an authorised scope file.")
            aid = cand.get("abuse_aid")
            if aid:
                tags.append("abuse_aid")
                forms = [f["abuse_form"] for f in aid["cdn_abuse_forms"] if f.get("abuse_form")]
                references += forms
                evidence.append(f"abuse aid: hoster {aid.get('hoster') or '?'} (ASN {aid.get('asn') or '?'}), abuse contact "
                                f"{aid.get('hoster_abuse_contact') or 'unknown'}, CDN abuse form(s): {', '.join(forms) or 'none verified'}")
                recommendation = ("Hostile site behind a CDN: report to the CDN first (abuse form) and mention the candidate origin as a "
                                  "hypothesis; the candidate hoster is unconfirmed. " + recommendation)
            if own and cand["strength"] == "strong":
                recommendation = ("Possible exposed origin of an own asset: if confirmed, the WAF/CDN can be bypassed - restrict the origin "
                                  "to the CDN's ranges. " + recommendation)
            out.append(Correlation(
                rule=RULE_ORIGIN,
                title=ORIGIN_TITLE,
                severity=severity,
                description=(f"{cand['value']} is a {LABEL} of {node.entity.value}, which is fronted by {fronted}"
                             + (f" since {result['cdn_since']}" if result["cdn_since"] else "")
                             + f": score {cand['score']:.2f} ({cand['strength']}) from {', '.join(kinds)}. Passive facts only: "
                             "V3LUM never connected to the address; it is not pivoted, expanded or used as a LIGHT/ACTIVE seed."),
                entities=[node.entity, ent],
                confidence="probable" if cand["strength"] == "strong" else "possible",
                evidence=evidence,
                recommendation=recommendation,
                tags=tags,
                references=references,
                why=f"{LABEL}: score {cand['score']:.2f} ({cand['strength']}) - {', '.join(kinds)}",
                key=cand["value"],
            ))
    return out


# ---- P371 FC5: corroboration of candidate SaaS tenants --------------------------------------------------------

#: P342 verification-record prefixes and P342 vendor names that corroborate a vendor.
_TXT_PREFIXES = {
    "atlassian": ("atlassian-domain-verification", "atlassian-sending-domain-verification"),
    "okta": ("okta-verification", "_oktaverification"),
    "zendesk": ("zendeskverification", "zendesk-verification"),
}


def _host_of(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".")


def _org_domains(graph: Any, node: Node) -> list[Node]:
    out = [node] if node.entity.type is T.DOMAIN else []
    for other in _nodes(graph):
        if other.entity.type is T.DOMAIN and (other.seed or getattr(other, "ownership", "") == "own_asset") and other not in out:
            out.append(other)
    return out


def tenant_corroboration(graph: Any, node: Node, row: Mapping[str, Any], adj: Mapping[str, list[Any]] | None = None) -> list[dict[str, str]]:
    """Graph facts that corroborate one 'exists' tenant row: P342 DNS verification (TXT prefix or saas_vendors name)
    and P011 identity-provider metadata (identity_provider edges, m365_identity_provider host). Token values are
    never echoed."""
    adj = adjacency(graph) if adj is None else adj
    vendor = str(row.get("vendor") or "")
    host = str(row.get("tenant_host") or "").lower()
    found: list[dict[str, str]] = []
    for dom in _org_domains(graph, node):
        name = str(dom.entity.value)
        vendors = {str(v).strip().lower() for v in _attr(dom, "saas_vendors") if isinstance(v, str)}
        txt = [str(v).strip().strip('"').lower() for v in _attr(dom, "txt") if isinstance(v, str)]
        prefix = next((p for t in txt for p in _TXT_PREFIXES.get(vendor, ()) if t.startswith(p)), None)
        if (vendor in vendors or prefix) and not any(c["kind"] == "dns_verification" for c in found):
            found.append({"kind": "dns_verification", "detail": f"{prefix or 'saas_vendors: ' + vendor} at {name}"})
        idp_hosts = [_host_of(v.get("host") or v.get("url")) for v in _attr(dom, "m365_identity_provider") if isinstance(v, Mapping)]
        idp_hosts += [e.dst.partition(":")[2] for e in _out(adj, dom.key, ("identity_provider",)) if e.module != TENANT_MODULE]
        if host and host in idp_hosts and not any(c["kind"] == "idp_issuer" for c in found):
            found.append({"kind": "idp_issuer", "detail": f"{host} is the federated identity provider of {name}"})
    return found


@rule(
    RULE_TENANT,
    TENANT_TITLE,
    "P371 FC5: a candidate SaaS tenant (Okta, Atlassian, Zendesk) found under the organisation's name is corroborated by a "
    "DNS verification record (P342) or identity-provider metadata (P011) of the organisation's domains.",
    version="1",
    severity="info",
    criterion="a tenant found by saas_tenant_discovery plus a P342 verification record or a P011 identity-provider host naming it",
    references=("https://attack.mitre.org/techniques/T1566/",),
    false_positives="A verification record proves a past domain verification at the vendor, not that this exact tenant is the "
                    "organisation's: the identity-provider match is stronger.",
)
def saas_tenant_corroborated(graph: Graph, results: list[Any], rctx: Any) -> list[Correlation]:
    out: list[Correlation] = []
    adj: dict[str, list[Any]] | None = None
    for node in _nodes(graph):
        for value, source in getattr(node, "attributes", {}).get("saas_tenant_checks", []):
            if source != TENANT_MODULE:
                continue
            rows = value if isinstance(value, list) else [value]
            for row in rows:
                if not isinstance(row, Mapping) or row.get("state") != "exists" or not row.get("tenant_host"):
                    continue
                if adj is None:
                    adj = adjacency(graph)
                found = list(row.get("corroboration") or []) or tenant_corroboration(graph, node, row, adj)
                if not found:
                    continue  # a homonym is never attributed by name alone
                tenant = Entity.try_make(T.DOMAIN, str(row["tenant_host"]))
                if tenant is None:
                    continue
                kinds = sorted({str(c.get("kind")) for c in found})
                out.append(Correlation(
                    rule=RULE_TENANT,
                    title=TENANT_TITLE,
                    severity=Severity.INFO,
                    description=(f"{row['tenant_host']} ({row.get('vendor')}) was found under the organisation's name and is corroborated by "
                                 f"{', '.join(kinds)}: an identity-provider/helpdesk tenant attackers may imitate in phishing. Its login "
                                 "pages are never contacted."),
                    entities=[node.entity, tenant],
                    confidence="probable",
                    evidence=[f"{c.get('kind')}: {str(c.get('detail'))[:160]}" for c in found]
                    + [f"vendor marker {row.get('marker')} (HTTP {row.get('http_status')})"],
                    recommendation="Record the tenant in the organisation profile (app_ids) after confirming it with the tenant's owner; use "
                                   "it for phishing-simulation and attack-surface planning.",
                    tags=["saas_tenant"],
                    why=f"tenant {row['tenant_host']} corroborated by {', '.join(kinds)}",
                    key=str(row["tenant_host"]),
                ))
    return out
