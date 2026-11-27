"""criminalip: Criminal IP asset reports of existing data for an IP, a domain or a URL host (keyed) (P048).

Batch p3-G02-1, proposal P048 (approved, P3). Final conditions implemented here:

* c1 - endpoint allow-list in code (:data:`ENDPOINTS`): the IP report and lookups of EXISTING domain
  reports only. The domain and URL 'scan' endpoints make Criminal IP crawl the target outside our ledger,
  so they are never wired in any mode: :func:`criminalip_url` cannot build them, and the domain flow
  never asks for a new scan (no report means EMPTY with that wording, never a scan).
* c2 - key ``criminalip`` (alias ``V3LUM_CRIMINALIP_KEY``), sent only in the ``x-api-key`` header.
  Key-terms: a company/team account on a plan recorded by legal (``key_plans.criminalip='business'``)
  before it runs under the corporate profile. ``default_enabled=False``.
* c3 - HTTP 200 with body status 403 ('check access failed') is caught by the provider marker
  ``criminalip_check_access_failed`` and reported as NEEDS_KEY. Credit wording gives QUOTA, body
  status 429 gives RATE_LIMITED and any other body status >= 400 gives ERROR. None of them is ever
  EMPTY. The plan's monthly credits are not recorded yet, so ``daily_quota`` is the P334 fallback and
  only seeds and depth-1 pivots spend credits.
* c4 - the inbound/outbound risk score is one vote (attribute ``criminalip_score``; a finding tagged
  ``weak_signal``, never 'malicious'). Ports and vulnerabilities are version-inferred and follow the P291
  caps: POSSIBLE, at most HIGH. The manual link is ``search.criminalip.io/asset/report/{ip}``.
* c5 - merge gate: the success fixtures are synthetic (field names recalled from the Criminal IP API
  documentation; no team-key capture exists). The recorded no-key answer is real.
  docs/backlog/p3-G02-1.md records the missing capture and the unverified ``/v1/domain/reports`` path.

Hostnames and domains become domain pivots with expand=False.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from v3lum.core.entities import Entity, url_host
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec, Status
from v3lum.core.module import Module, register
from v3lum.modules.ip_network.scan_engines import (
    VERSION_INFERRED_CRITERION,
    EndpointRefused,
    apex_of,
    as_dict,
    as_list,
    cve_id,
    fetch_json,
    flag,
    in_apex,
    integer,
    json_cache_veto,
    normalize_domain,
    normalize_ip,
    number,
    port,
    public_ip,
    text,
    vuln_severity,
    worst,
)

SOURCE = "criminalip.asset_api"
KEY = "criminalip"
API = "https://api.criminalip.io"
REPORT_PAGE = "https://search.criminalip.io/asset/report/{ip}"
#: c1: op -> path template. Existing-data lookups only; no scan, status or private-scan endpoint exists here.
ENDPOINTS: dict[str, str] = {
    "ip_report": "/v1/asset/ip/report",
    "domain_reports": "/v1/domain/reports",
    "domain_report": "/v2/domain/report/{scan_id}",
}
NEEDS_KEY_MARKERS = frozenset({"criminalip_check_access_failed"})
#: Criminal IP score words -> rank (Safe < Low < Moderate < Dangerous < Critical)
SCORE_RANK = {"safe": 0, "low": 1, "moderate": 2, "dangerous": 3, "critical": 4}
ISSUE_FLAGS = {"is_vpn": "is_vpn", "is_proxy": "is_proxy", "is_hosting": "is_hosting", "is_scanner": "is_scanner",
               "is_cloud": "cloud", "is_tor": "tor", "is_anonymous_vpn": "anonymous_vpn", "is_darkweb": "darkweb",
               "is_mobile": "mobile", "is_snort": "snort"}
NAME_PIVOT_CAP = 20
ALERT_CAP = 20


def criminalip_url(op: str, value: str = "") -> tuple[str, dict[str, str]]:
    """(url, params) of one wired endpoint (c1). Raises EndpointRefused for the domain/URL scan
    endpoints, scan status/private/lite paths and anything else; ValueError for an invalid value."""
    name = str(op or "").strip()
    if name not in ENDPOINTS:
        raise EndpointRefused(f"Criminal IP endpoint {name!r} is never wired: existing-data lookups only, the scan "
                              "endpoints make Criminal IP crawl the target (P048 cond 1)")
    path = ENDPOINTS[name]
    if name == "ip_report":
        ip = public_ip(value)
        if not ip:
            raise ValueError("Criminal IP IP reports take a public IP address")
        return API + path, {"ip": ip}
    if name == "domain_reports":
        dom = normalize_domain(value)
        if not dom:
            raise ValueError("Criminal IP domain reports take a domain")
        return API + path, {"query": dom, "offset": "0"}
    scan_id = integer(value)
    if scan_id is None or scan_id <= 0:
        raise ValueError("Criminal IP domain report ids are positive integers")
    return API + path.format(scan_id=quote(str(scan_id))), {}


def _section(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [as_dict(x) for x in as_list(as_dict(data.get(key)).get("data")) if isinstance(x, dict)]


def score_vote(inbound: str, outbound: str) -> str:
    """c4: one vote from the worse of the inbound and outbound scores."""
    rank = max(SCORE_RANK.get(inbound.lower(), -1), SCORE_RANK.get(outbound.lower(), -1))
    if rank >= 3:
        return "malicious"
    if rank == 2:
        return "suspicious"
    return "benign" if rank >= 0 else "unknown"


def parse_ip_report(data: Any) -> dict[str, Any] | None:
    """/v1/asset/ip/report -> facts; None when the body is not an IP report."""
    if not isinstance(data, dict) or not any(k in data for k in ("issues", "score", "port", "whois")):
        return None
    status = integer(data.get("status"))
    if status is not None and status != 200:
        return None
    score = as_dict(data.get("score"))
    inbound, outbound = text(score.get("inbound"), 20), text(score.get("outbound"), 20)
    issues = as_dict(data.get("issues"))
    flags = sorted(name for key, name in ISSUE_FLAGS.items() if flag(issues.get(key)) is True)
    ports, services, products = set(), [], []
    for row in _section(data, "port")[:100]:
        p = port(row.get("open_port_no"))
        if p is None:
            continue
        ports.add(p)
        app = " ".join(x for x in (text(row.get("app_name"), 60), text(row.get("app_version"), 40)) if x)
        services.append(f"{p}/{text(row.get('socket'), 8) or 'tcp'} {text(row.get('protocol'), 20) or '?'}" + (f" {app}" if app else ""))
        if app and app not in products:
            products.append(app)
    vulns: dict[str, dict[str, Any]] = {}
    for row in _section(data, "vulnerability")[:200]:
        cid = cve_id(row.get("cve_id"))
        if not cid:
            continue
        cvss = number(row.get("cvssv3_score")) or number(row.get("cvssv2_score"))
        tcp = [p for p in (port(x) for x in as_list(as_dict(row.get("open_port_no_list")).get("TCP"))) if p]
        entry = vulns.setdefault(cid, {"cve": cid, "cvss": cvss, "product": " ".join(x for x in (text(row.get("app_name"), 60), text(row.get("app_version"), 40)) if x),
                                       "ports": tcp[:10], "verified": False})
        if cvss is not None and (entry["cvss"] is None or cvss > entry["cvss"]):
            entry["cvss"] = cvss
    alerts = []
    for row in _section(data, "ids")[:ALERT_CAP]:
        alerts.append({k: v for k, v in {"classification": text(row.get("classification"), 80), "message": text(row.get("message"), 160),
                                         "source_system": text(row.get("source_system"), 40),
                                         "confirmed_time": text(row.get("confirmed_time"), 40)}.items() if v})
    for row in _section(data, "honeypot")[:ALERT_CAP]:
        alerts.append({k: v for k, v in {"classification": "honeypot", "message": text(row.get("message"), 160),
                                         "source_system": "honeypot", "dst_port": port(row.get("dst_port")),
                                         "confirmed_time": text(row.get("confirmed_time"), 40) or text(row.get("log_date"), 40)}.items() if v})
    whois = (_section(data, "whois") or [{}])[0]
    asn = integer(whois.get("as_no"))
    names: list[str] = []
    for row in _section(data, "hostname"):
        n = normalize_domain(row.get("domain_name_full") or row.get("domain_name_rep"))
        if n and n not in names:
            names.append(n)
    domains: list[str] = []
    for row in _section(data, "domain"):
        n = normalize_domain(row.get("domain"))
        if n and n not in domains and n not in names:
            domains.append(n)
    categories = sorted({text(row.get("type"), 40).lower() for row in _section(data, "ip_category")} - {""})
    out = {"inbound": inbound, "outbound": outbound, "vote": score_vote(inbound, outbound), "flags": flags,
           "ports": sorted(ports), "services": services[:50], "products": products[:50], "vulns": list(vulns.values()),
           "alerts": alerts, "asn": f"AS{asn}" if asn and asn > 0 else "", "as_org": text(whois.get("org_name"), 160) or text(whois.get("as_name"), 160),
           "country": text(whois.get("org_country_code"), 2).upper(), "hostnames": names[:50], "domains": domains[:50],
           "categories": categories[:20]}
    out["empty"] = not any((ports, vulns, alerts, names, domains, categories, flags, out["asn"])) and out["vote"] in ("benign", "unknown")
    return out


def parse_domain_reports(data: Any) -> list[dict[str, Any]] | None:
    """/v1/domain/reports -> existing reports [{scan_id, reg_dtime, url, score}] newest first; None if not a list answer."""
    body = as_dict(data)
    reports = as_dict(body.get("data")).get("reports")
    if integer(body.get("status")) not in (None, 200) or not isinstance(reports, list):
        return None
    out = []
    for row in reports:
        row = as_dict(row)
        sid = integer(row.get("scan_id"))
        if sid is None or sid <= 0:
            continue
        out.append({"scan_id": sid, "reg_dtime": text(row.get("reg_dtime"), 40), "url": text(row.get("url"), 300),
                    "score": text(row.get("score"), 20), "issues": [text(x, 40) for x in as_list(row.get("issue")) if text(x, 40)][:10]})
    return sorted(out, key=lambda r: (r["reg_dtime"], r["scan_id"]), reverse=True)


def parse_domain_report(data: Any) -> dict[str, Any] | None:
    """/v2/domain/report/{scan_id} -> {ips, domains, urls, certificates}; None when not a report."""
    body = as_dict(data)
    rep = body.get("data")
    if integer(body.get("status")) not in (None, 200) or not isinstance(rep, dict):
        return None
    ips: list[str] = []
    for row in as_list(rep.get("connected_ip_info")):
        ip = normalize_ip(as_dict(row).get("ip"))
        if ip and ip not in ips:
            ips.append(ip)
    for row in as_list(as_dict(as_dict(rep.get("dns_record")).get("dns_record_type_a")).get("ipv4")):
        ip = normalize_ip(as_dict(row).get("ip"))
        if ip and ip not in ips:
            ips.append(ip)
    domains: list[str] = []
    for group in as_list(rep.get("connected_domain_subdomain")):
        group = as_dict(group)
        for row in [as_dict(group.get("main_domain"))] + [as_dict(x) for x in as_list(group.get("subdomains"))]:
            n = normalize_domain(row.get("domain"))
            if n and n not in domains:
                domains.append(n)
    for row in as_list(rep.get("subdomains")):
        n = normalize_domain(as_dict(row).get("subdomain_name"))
        if n and n not in domains:
            domains.append(n)
    linked = [n for n in (normalize_domain(as_dict(r).get("domain")) for r in as_list(rep.get("html_page_link_domains"))) if n]
    certs = [{"subject": text(as_dict(c).get("subject"), 200), "issuer": text(as_dict(c).get("issuer"), 200)} for c in as_list(rep.get("certificates"))[:10]]
    return {"ips": ips[:50], "domains": domains[:50], "linked_domains": linked[:50], "certificates": [c for c in certs if c["subject"] or c["issuer"]]}


def _ok_ip(data: Any) -> bool:
    return parse_ip_report(data) is not None


@register
class CriminalIp(Module):
    name = "criminalip"
    title = "Criminal IP asset report"
    description = (
        "Inbound/outbound risk score (one vote), VPN/proxy/hosting/scanner flags, open ports, version-inferred CVEs, "
        "IDS/honeypot alerts and hostnames of an IP, and existing domain reports (no new scan), from Criminal IP (keyed)."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.DOMAIN, T.URL}
    produces = {T.DOMAIN, T.IPV4, T.IPV6}
    reference = "https://www.criminalip.io/developer/api"
    notice = (
        "Keyed (criminalip): key-terms - a company/team account on a plan recorded by legal (key_plans.criminalip="
        "'business'). Existing reports only: the domain/URL scan endpoints (Criminal IP crawls the target) are never "
        "wired. Risk scores are one vote. Foreign provider (KR): queries are logged abroad."
    )
    terms = "key-terms"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "criminalip"
    sources = (SOURCE,)
    hosts = ("api.criminalip.io",)
    access_model = "free_auth_limited"
    requires_keys = (KEY,)
    max_requests = 2
    expected_latency = 2.0
    timeout = 30.0
    min_interval = 1.0
    daily_quota = 30  # fallback until the plan's monthly credits are recorded as a quota block (P334)
    cache_ttl = 86400
    max_pivots = 50
    manual_link = REPORT_PAGE
    default_enabled = False

    @staticmethod
    def _target(entity: Entity) -> tuple[str, str] | None:
        """('ip'|'domain', value) of the entity; a URL contributes only its host (never its path)."""
        value = entity.value
        if entity.type is T.URL:
            value = url_host(entity.value) or ""
        ip = normalize_ip(value)
        if ip:
            return ("ip", ip) if public_ip(ip) else None
        dom = normalize_domain(value)
        return ("domain", dom) if dom else None

    def applies(self, entity: Entity, ctx: Any) -> bool:
        if int(getattr(ctx, "depth", 0) or 0) > 1:
            return False  # credits: seeds and first-level pivots only
        return self._target(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        key = str(ctx.key(KEY) or "").strip()
        if not key:
            return res.mark(Status.NEEDS_KEY, "Criminal IP needs the key 'criminalip' (V3LUM_CRIMINALIP_KEY)", reason_code="needs_key")
        target = self._target(entity)
        if target is None:
            return res.mark(Status.SKIPPED, "no public IP or domain to look up", reason_code="not_applicable")
        kind, value = target
        headers = {"x-api-key": key}
        if kind == "ip":
            return self._ip(res, entity, ctx, value, headers)
        return self._domain(res, entity, ctx, value, headers)

    # ---- IP report ------------------------------------------------------------------------

    def _ip(self, res: ModuleResult, entity: Entity, ctx: Any, ip: str, headers: dict[str, str]) -> ModuleResult:
        url, params = criminalip_url("ip_report", ip)
        data = fetch_json(ctx, "GET", url, source=SOURCE, headers=headers, params=params, needs_key_markers=NEEDS_KEY_MARKERS,
                          ttl=self.cache_ttl, cache_if=json_cache_veto(_ok_ip), provider_label="Criminal IP")
        parsed = parse_ip_report(data)
        if parsed is None:
            return res.mark(Status.ERROR, "unexpected Criminal IP report answer: could not verify", reason_code="error")
        res.link("Criminal IP asset report (manual; foreign provider: queries are logged abroad)", REPORT_PAGE.format(ip=ip))
        res.raw = {"ip_report": parsed}
        res.attr("criminalip_score", {"inbound": parsed["inbound"], "outbound": parsed["outbound"], "vote": parsed["vote"]})
        if parsed["empty"]:
            return res.mark(Status.EMPTY, f"Criminal IP holds no record for {ip} (scores {parsed['inbound'] or '?'}/{parsed['outbound'] or '?'})")
        for flag_name in parsed["flags"]:
            if flag_name in ("is_vpn", "is_proxy", "is_hosting", "is_scanner"):
                res.attr(flag_name, True)
        res.attr("context_tags", [f for f in parsed["flags"] if not f.startswith("is_")])
        res.attr("tags", parsed["categories"])
        res.attr("asn", parsed["asn"])
        res.attr("as_org", parsed["as_org"])
        res.attr("country", parsed["country"])
        res.attr("open_ports", parsed["ports"])
        res.attr("services", parsed["services"])
        res.attr("technologies", parsed["products"])
        res.attr("ids_alerts", parsed["alerts"])
        self._vote(res, ip, parsed)
        self._vulns(res, ip, parsed)
        for name in parsed["hostnames"][:NAME_PIVOT_CAP]:
            res.pivot(T.DOMAIN, name, "reverse_dns", confidence="possible", expand=False,
                      note="hostname Criminal IP associates with the address: listed, not expanded (P048)")
        for name in parsed["domains"][:NAME_PIVOT_CAP]:
            res.pivot(T.DOMAIN, name, "hosted_domain", confidence="possible", expand=False,
                      note="domain Criminal IP saw on the address: listed, not expanded (P048)")
        return res

    def _vote(self, res: ModuleResult, ip: str, parsed: dict[str, Any]) -> None:
        vote = parsed["vote"]
        if vote not in ("malicious", "suspicious"):
            return
        res.finding(
            "Criminal IP risk score (one vote)",
            "medium" if vote == "malicious" else "low",
            f"Criminal IP scores {ip} inbound '{parsed['inbound'] or '?'}' / outbound '{parsed['outbound'] or '?'}'. A vendor "
            "risk score is one vote for consensus, never a verdict on its own.",
            confidence="possible",
            criterion="Criminal IP inbound/outbound score Moderate or worse (one vendor vote, P048 cond 4)",
            data={"inbound": parsed["inbound"], "outbound": parsed["outbound"], "vote": vote},
            tags=["weak_signal", "third_party_verdict"],
            source=SOURCE,
        )

    def _vulns(self, res: ModuleResult, ip: str, parsed: dict[str, Any]) -> None:
        vulns = parsed["vulns"]
        if not vulns:
            return
        res.attr("vulns", [v["cve"] for v in vulns][:100])
        products = sorted({v["product"] for v in vulns if v["product"]})
        res.finding(
            "CVE(s) associated with exposed software (version-inferred)",
            worst(vuln_severity(v["cvss"]) for v in vulns),
            f"Criminal IP lists {len(vulns)} CVE(s) for software versions on {ip}"
            f"{' (' + ', '.join(products[:5]) + ')' if products else ''}. Version-inferred: confirm on the host.",
            confidence="possible",
            criterion=VERSION_INFERRED_CRITERION,
            data={"vulns": vulns[:50]},
            tags=["vulnerable", "version_inferred"],
            source=SOURCE,
        )

    # ---- domain: existing reports only -------------------------------------------------------

    def _domain(self, res: ModuleResult, entity: Entity, ctx: Any, domain: str, headers: dict[str, str]) -> ModuleResult:
        url, params = criminalip_url("domain_reports", domain)
        data = fetch_json(ctx, "GET", url, source=SOURCE, headers=headers, params=params, needs_key_markers=NEEDS_KEY_MARKERS,
                          ttl=self.cache_ttl, cache_if=json_cache_veto(lambda d: parse_domain_reports(d) is not None),
                          provider_label="Criminal IP")
        reports = parse_domain_reports(data)
        if reports is None:
            return res.mark(Status.ERROR, "unexpected Criminal IP domain reports answer: could not verify", reason_code="error")
        res.raw = {"domain": domain, "reports": reports[:10]}
        if not reports:
            return res.mark(Status.EMPTY, f"Criminal IP holds no existing report for {domain} (V3LUM never requests a new scan)")
        latest = reports[0]
        url, params = criminalip_url("domain_report", str(latest["scan_id"]))
        data = fetch_json(ctx, "GET", url, source=SOURCE, headers=headers, params=params, needs_key_markers=NEEDS_KEY_MARKERS,
                          ttl=self.cache_ttl, cache_if=json_cache_veto(lambda d: parse_domain_report(d) is not None),
                          provider_label="Criminal IP")
        report = parse_domain_report(data)
        if report is None:
            return res.mark(Status.ERROR, "unexpected Criminal IP domain report answer: could not verify", reason_code="error")
        res.raw["report"] = {"scan_id": latest["scan_id"], **report}
        res.attr("third_party_scans", [{"source": "criminalip", "report_id": r["scan_id"], "scan_date": r["reg_dtime"],
                                         "score": r["score"]} for r in reports[:10]])
        apex = apex_of(entity) or domain
        for ip in report["ips"][:NAME_PIVOT_CAP]:
            res.pivot(T.IPV6 if ":" in ip else T.IPV4, ip, "resolves_to", confidence="possible", expand=False,
                      note=f"address in the Criminal IP report of {latest['reg_dtime'] or 'an earlier date'}: re-resolve before acting")
        for name in report["domains"][:NAME_PIVOT_CAP]:
            if name == domain:
                continue
            res.pivot(T.DOMAIN, name, "subdomain" if in_apex(name, apex) else "related", confidence="possible", expand=False,
                      note="name in an existing Criminal IP report: listed, not expanded (P048)")
        for name in report["linked_domains"][:NAME_PIVOT_CAP]:
            res.pivot(T.DOMAIN, name, "links_to", confidence="possible", expand=False,
                      note="domain linked from the page in an existing Criminal IP report: listed, not expanded")
        res.finding("Existing Criminal IP domain report", "info",
                    f"{len(reports)} existing report(s) for {domain}; the latest ({latest['reg_dtime'] or '?'}) lists "
                    f"{len(report['ips'])} address(es) and {len(report['domains'])} name(s). No new scan is ever requested.",
                    confidence="possible", data={"scan_id": latest["scan_id"], "score": latest["score"]}, source=SOURCE,
                    observed_last=latest["reg_dtime"] or None)
        return res


__all__ = ["CriminalIp", "criminalip_url", "parse_domain_report", "parse_domain_reports", "parse_ip_report", "score_vote"]
