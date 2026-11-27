"""honeypot_intel_extra: HoneyLabs CVE telemetry and the jamesbrine.com.au attack feeds (P147 c3, c4).

Batch p2-G02-2, proposal P147. These feeds publish no licence the council could record (c3), so they
ship as this separate opt-in module: ``default_enabled=False``, terms 'unknown', tier unknown,
disabled in every profile until legal records their terms (the licence gate never lets an
'unknown' source run; the tier gate excludes unknown-tier providers at AMBER and above and they
receive IOC values only). When cleared (c4):

* HoneyLabs keyless ``GET /api/cves/{cve}`` (registry source ``honeylabs.api``, the shared
  ``honeylabs`` seed): ``actively_exploited``, KEV, exploit patterns, events and the 'actors'
  capped at the top :data:`MAX_ACTORS` (20) IPs by events, listed as ``expand=False`` pivots;
  UDP-derived actors are excluded (c7). Keyed IP lookups (/lookup/{ip} JSON with the free key) are
  not wired: no recorded answer exists to build the parser from (docs/backlog/p2-G02-2.md).
* jamesbrine.com.au ``iplist.txt`` and ``/csv`` as registered datasets matched locally through the
  core dataset index (never the 14 MB ``type_*.json`` files).

Both use the honeypot semantics of ``honeypot_intel`` (c6): tag ``scanner``, at most MEDIUM alone,
30-day decay, never ``malicious``.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any

from v3lum.core import noise
from v3lum.core.datasets import DatasetError, register_dataset
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.threat_intel_ioc.honeypot_intel import (
    dataset_failure,
    honeypot_verdict,
    iso,
    looks_like_html,
    memo,
    norm_ip,
    parse_ip_list,
    parse_ts,
    text_lines,
)

SRC_HONEYLABS = "honeylabs.api"
SRC_JB_IPLIST = "jamesbrine.iplist"
SRC_JB_ACTIVITY = "jamesbrine.activity"
HONEYLABS_CVE = "https://honeylabs.net/api/cves/{cve}"
MAX_ACTORS = 20  # c4: the top 20 actor IPs
MAX_PATTERNS = 20
JB_NOTE = ("jamesbrine.com.au threat feeds: no licence published (site FAQ: TLP:White, free for non-commercial purposes, "
           "commercial use needs prior approval); runtime download only, never redistributed")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
JB_HEADER = ["ipv4", "activity", "date"]


def _validate_jb_iplist(path: Path) -> bool:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if looks_like_html(raw):
        raise ValueError("HTML page instead of the iplist.txt list")
    ips, invalid = parse_ip_list(raw)
    if not ips:
        raise ValueError("no IP address in iplist.txt")
    if invalid > max(5, len(ips) // 20):
        raise ValueError(f"{invalid} lines of iplist.txt are not IP addresses")
    return True


def parse_jb_activity(raw: str) -> dict[str, list[dict[str, str]]]:
    """jamesbrine.com.au /csv ('ipv4, activity, date') -> {ip: [{activity, date}]}. Raises ValueError
    for an HTML page or another header; malformed rows are skipped."""
    if looks_like_html(raw):
        raise ValueError("HTML page instead of the activity CSV")
    lines, _dropped = text_lines(raw.lstrip("﻿"))
    rows = list(csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True))
    if not rows or [h.strip().lower() for h in rows[0]] != JB_HEADER:
        raise ValueError("unexpected activity CSV header (expected 'ipv4, activity, date')")
    out: dict[str, list[dict[str, str]]] = {}
    for row in rows[1:10_001]:
        if len(row) != 3:
            continue
        ip = norm_ip(row[0])
        if ip is None or parse_ts(row[2].strip()) is None:
            continue
        out.setdefault(ip, []).append({"activity": row[1].strip()[:80], "date": row[2].strip()[:10]})
    return out


def _validate_jb_activity(path: Path) -> bool:
    parse_jb_activity(path.read_text(encoding="utf-8", errors="replace"))
    return True


JB_IPLIST = register_dataset(
    "honeypot_intel_extra.jamesbrine_iplist.txt",
    "https://jamesbrine.com.au/iplist.txt",
    ttl=86400,
    description="jamesbrine.com.au iplist.txt: aggregated IPv4 addresses seen brute-forcing/attacking the operator's honeypots",
    licence="LicenseRef-unknown-no-licence-published",
    terms_class="unknown",
    attribution=JB_NOTE,
    provider="jamesbrine",
    source=SRC_JB_IPLIST,
    validate=_validate_jb_iplist,
    min_bytes=7,
    expect="lines",
    max_bytes=4 * 1024 * 1024,
    large=False,
)
JB_ACTIVITY = register_dataset(
    "honeypot_intel_extra.jamesbrine_activity.csv",
    "https://jamesbrine.com.au/csv",
    ttl=86400,
    description="jamesbrine.com.au /csv: activity label and date of the latest day's addresses",
    licence="LicenseRef-unknown-no-licence-published",
    terms_class="unknown",
    attribution=JB_NOTE,
    provider="jamesbrine",
    source=SRC_JB_ACTIVITY,
    validate=_validate_jb_activity,
    min_bytes=20,
    expect="csv",
    max_bytes=1024 * 1024,
    large=False,
)


def parse_honeylabs_cve(doc: Any, *, max_actors: int = MAX_ACTORS) -> dict[str, Any]:
    """HoneyLabs keyless /api/cves/{cve} (c4). Actors are capped at the top ``max_actors`` IPs by
    events; actors flagged as UDP-derived are excluded (c7). Raises ValueError for an answer that is
    not a CVE object."""
    if not isinstance(doc, dict):
        raise ValueError("unexpected HoneyLabs answer (not an object): could not verify")
    if isinstance(doc.get("error"), str):
        raise ValueError(f"HoneyLabs: {doc['error'][:120]}")
    cve = doc.get("cve_id") if isinstance(doc.get("cve_id"), str) else ""
    if not _CVE_RE.match(cve.strip()):
        raise ValueError("HoneyLabs answer without a CVE id: could not verify")
    kev = doc.get("kev") if isinstance(doc.get("kev"), dict) else {}
    notice = doc.get("window_notice") if isinstance(doc.get("window_notice"), dict) else {}

    def num(value: Any) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    actors: list[dict[str, Any]] = []
    excluded_udp = 0
    for item in doc.get("actors") or [] if isinstance(doc.get("actors"), list) else []:
        if isinstance(item, str):
            item = {"ip": item}
        if not isinstance(item, dict) or norm_ip(item.get("ip")) is None:
            continue
        if str(item.get("protocol") or item.get("transport") or "").strip().lower() == "udp":
            excluded_udp += 1
            continue
        asn = item.get("asn")
        actors.append({
            "ip": norm_ip(item["ip"]), "events": num(item.get("events")),
            "asn": f"AS{asn}" if isinstance(asn, int) and not isinstance(asn, bool) and 0 < asn < 2**32 else None,
            "asn_org": str(item.get("asn_org"))[:120] if isinstance(item.get("asn_org"), str) else None,
            "country": str(item.get("country_code"))[:2].upper() if isinstance(item.get("country_code"), str) else None,
            "last_seen": iso(parse_ts(item.get("last_seen"))),
        })
    actors.sort(key=lambda a: (-a["events"], a["ip"]))
    returned_days = num(notice.get("returned_days")) or (num(doc.get("window_hours")) // 24)
    return {
        "cve": cve.strip().upper(),
        "actively_exploited": doc.get("actively_exploited") if isinstance(doc.get("actively_exploited"), bool) else None,
        "kev": bool(kev) or bool(doc.get("kev_date_added")),
        "kev_date_added": str(doc.get("kev_date_added") or kev.get("date_added") or "")[:10] or None,
        "events": num(doc.get("events")), "unique_ips": num(doc.get("unique_ips")),
        "window": f"{returned_days}d" if returned_days else None,
        "patterns": [p[:120] for p in doc.get("patterns") or [] if isinstance(p, str)][:MAX_PATTERNS]
        if isinstance(doc.get("patterns"), list) else [],
        "actors": actors[:max_actors], "actors_total": len(actors), "actors_excluded_udp": excluded_udp,
        "top_asns": [{"asn": f"AS{a['asn']}", "org": str(a.get("org") or "")[:120]} for a in doc.get("top_asns") or []
                     if isinstance(a, dict) and isinstance(a.get("asn"), int) and not isinstance(a.get("asn"), bool)][:10]
        if isinstance(doc.get("top_asns"), list) else [],
    }


@register
class HoneypotIntelExtra(Module):
    name = "honeypot_intel_extra"
    title = "Honeypot intelligence, unreviewed feeds (HoneyLabs, jamesbrine.com.au)"
    description = (
        "HoneyLabs keyless CVE exploitation telemetry (top 20 attacking IPs) and the jamesbrine.com.au attack IP feeds matched "
        "locally. Opt-in: both publish no licence the council could record (terms and tier unknown)."
    )
    category = "threat_intel_ioc"
    accepts = {T.IPV4, T.CVE}
    produces = {T.IPV4}
    tags = {"reputation", "free"}  # the IPv4 path is an attack-IP list (counted by the WP14 reading once enabled)
    reference = "https://honeylabs.net/docs"
    notice = (
        "HoneyLabs and jamesbrine.com.au publish no licence the council recorded (P147 c3): terms 'unknown', tier unknown, "
        "disabled in every profile until legal records their terms. Honeypot sightings mean opportunistic scanning, never "
        "'malicious'. UDP-derived sources are excluded."
    )
    terms = "unknown"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "honeylabs"
    sources = (SRC_HONEYLABS, SRC_JB_IPLIST, SRC_JB_ACTIVITY)
    hosts = ("honeylabs.net",)
    access_model = "free_noauth_limited"
    max_requests = 1
    expected_latency = 1.0
    min_interval = 1.0
    cache_ttl = 21600  # CVE telemetry answers: 6 h
    max_pivots = MAX_ACTORS
    default_enabled = False  # unknown terms and tier (P147 c3, A3)

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return entity.type is not T.IPV4 or noise.is_public_ip(entity.value)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        allowed = ctx.allowed_sources
        if entity.type is T.CVE:
            for sid in (SRC_JB_IPLIST, SRC_JB_ACTIVITY):
                if sid in allowed:
                    res.source_status(sid, Status.SKIPPED, reason_code="not_applicable", reason="IPv4 feed")
            if SRC_HONEYLABS not in allowed:
                return res.mark(Status.SKIPPED, "HoneyLabs is not allowed (terms 'unknown' until legal records them)", reason_code="licence")
            return self._cve(res, entity, ctx)
        if SRC_HONEYLABS in allowed:
            res.source_status(SRC_HONEYLABS, Status.SKIPPED, reason_code="not_applicable",
                              reason="HoneyLabs keyed IP lookups are not wired (no recorded answer; backlog)")
        if SRC_JB_IPLIST not in allowed:
            return res.mark(Status.SKIPPED, "jamesbrine.com.au feeds are not allowed (terms 'unknown' until legal records them)", reason_code="licence")
        return self._ip(res, entity, ctx, allowed)

    # ---- HoneyLabs CVE (c4) --------------------------------------------------------------------
    def _cve(self, res: ModuleResult, entity: Entity, ctx: Any) -> ModuleResult:
        try:
            doc = ctx.http.get_json(HONEYLABS_CVE.format(cve=entity.value.upper()), source=SRC_HONEYLABS)
            data = parse_honeylabs_cve(doc)
        except ValueError as exc:
            return res.mark(Status.ERROR, f"{str(exc)[:200]}: could not verify", reason_code="error")
        if data["cve"] != entity.value.upper():
            return res.mark(Status.ERROR, f"HoneyLabs answered for {data['cve']}, not {entity.value}: could not verify", reason_code="error")
        res.raw = {k: v for k, v in data.items() if k != "actors"} | {"actors": [a["ip"] for a in data["actors"]]}
        activity = {"source": "honeylabs", "window": data["window"], "actively_exploited": data["actively_exploited"], "kev": data["kev"],
                    "events": data["events"], "unique_ips": data["unique_ips"], "patterns": data["patterns"], "top_asns": data["top_asns"],
                    "actors_shown": len(data["actors"]), "actors_excluded_udp": data["actors_excluded_udp"]}
        res.attr("honeypot_cve_activity", activity)
        if data["actively_exploited"] is True:
            res.attr("exploited_in_wild", True)
        if data["events"] <= 0:
            return res  # HoneyLabs answered: no attempts in its window (facts kept, no finding)
        lasts = sorted(a["last_seen"] for a in data["actors"] if a["last_seen"])
        res.finding(
            "Exploitation attempts seen by HoneyLabs honeypots",
            "low",
            f"{data['events']} events from {data['unique_ips']} source addresses in the last {data['window'] or 'window'} "
            f"(top {len(data['actors'])} shown{', KEV' if data['kev'] else ''}); exploit patterns: {', '.join(data['patterns'][:5]) or 'n/a'}.",
            confidence="possible",
            criterion="HoneyLabs CVE telemetry counts exploit attempts against its own honeypots (closed-source collection, terms unreviewed)",
            data=activity,
            tags=["kev"] if data["kev"] else [],
            references=[f"https://honeylabs.net/api/cves/{entity.value.upper()}"],
            source=SRC_HONEYLABS,
            observed_last=lasts[-1] if lasts else None,
        )
        for actor in data["actors"]:
            res.pivot(T.IPV4, actor["ip"], "exploit_attempted_by", confidence="possible", expand=False,
                      note=f"seen by HoneyLabs honeypots ({actor['events']} events): analyst selection required")
        return res

    # ---- jamesbrine.com.au feeds (c4) ------------------------------------------------------------
    def _ip(self, res: ModuleResult, entity: Entity, ctx: Any, allowed: frozenset[str]) -> ModuleResult:
        ip = norm_ip(entity.value) or entity.value
        try:
            listed = bool(ctx.data.index(JB_IPLIST, fmt="lines").contains(ip))
        except (DatasetError, OSError, ValueError) as exc:
            status, code = dataset_failure(exc) if isinstance(exc, DatasetError) else (Status.ERROR, "error")
            res.source_status(SRC_JB_IPLIST, status, reason_code=code, reason=f"iplist.txt unavailable: {str(exc)[:200]}")
            return res.mark(status, f"jamesbrine.com.au iplist.txt unavailable ({str(exc)[:160]}): could not verify", reason_code=code)
        res.source_status(SRC_JB_IPLIST, Status.OK if listed else Status.EMPTY)
        activity: list[dict[str, str]] = []
        if SRC_JB_ACTIVITY in allowed:
            try:
                path = Path(ctx.data.fetch(JB_ACTIVITY))
                info = ctx.data.info(JB_ACTIVITY)
                table = memo(JB_ACTIVITY, str(info.sha256 or ""), lambda: parse_jb_activity(path.read_text(encoding="utf-8", errors="replace")))
                activity = list(table.get(ip, []))
                res.source_status(SRC_JB_ACTIVITY, Status.OK if activity else Status.EMPTY)
            except (DatasetError, OSError, ValueError) as exc:
                status, code = dataset_failure(exc) if isinstance(exc, DatasetError) else (Status.ERROR, "error")
                res.source_status(SRC_JB_ACTIVITY, status, reason_code=code, reason=f"activity CSV unavailable: {str(exc)[:200]}")
        if not listed and not activity:
            return res.mark("empty")
        last = max((a["date"] for a in activity), default=None)
        verdict = honeypot_verdict(now=ctx.now(), transport="unknown", last_seen=last)
        sighting = {"source": "jamesbrine", "listed": listed, "activity": activity, "last_seen": last, "decay": verdict.decay,
                    "counts_for_verdict": verdict.counts}
        res.raw = sighting
        res.attr("honeypot_sightings", [sighting])
        res.attr("is_scanner", True)
        labels = sorted({a["activity"] for a in activity})
        res.finding(
            "Listed in the jamesbrine.com.au attack feeds",
            verdict.severity,
            f"Listed in jamesbrine.com.au iplist.txt (aggregated addresses seen attacking the operator's honeypots)"
            f"{'; latest activity: ' + ', '.join(labels) + ' on ' + str(last) if labels else ''}. {verdict.why}.",
            confidence="possible",
            criterion=f"listed in the jamesbrine.com.au feed (single operator, terms unreviewed); {verdict.why}",
            data=sighting,
            tags=verdict.tags,
            references=["https://jamesbrine.com.au/"],
            source=SRC_JB_IPLIST if listed else SRC_JB_ACTIVITY,
            observed_last=last,
        )
        return res
