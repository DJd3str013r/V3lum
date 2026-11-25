"""Shodan InternetDB: open ports, hostnames, CPEs, tags and CVEs for an IP (free, no key).

Reference implementation for HTTP API modules.
"""

from __future__ import annotations

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API (unauthenticated)", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 5601: "Kibana", 8086: "InfluxDB", 9000: "admin panel / PHP-FPM",
}


@register
class ShodanInternetDB(Module):
    name = "shodan_internetdb"
    title = "Shodan InternetDB"
    description = "Open ports, hostnames, CPEs, tags and known CVEs for an IP from Shodan's free InternetDB."
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.DOMAIN, T.CVE}
    hosts = ("internetdb.shodan.io",)
    reference = "https://internetdb.shodan.io/docs"
    tags = {"free", "core"}
    cache_ttl = 86400

    def applies(self, entity: Entity, ctx: object) -> bool:
        return is_public_ip(entity.value)

    def run(self, entity: Entity, ctx: object) -> ModuleResult:
        res = self.result(entity)
        r = ctx.http.get(f"https://internetdb.shodan.io/{entity.value}", headers={"Accept": "application/json"})
        if r.status == 404:
            return res.mark("empty")
        r.raise_for_status()
        data = r.json()
        res.raw = data
        ports = sorted(int(p) for p in data.get("ports", []) if str(p).isdigit())
        res.attr("open_ports", ports)
        res.attr("hostnames", data.get("hostnames"))
        res.attr("cpes", data.get("cpes"))
        res.attr("tags", data.get("tags"))
        res.attr("vulns", data.get("vulns"))
        shared_edge = bool({"cdn", "cloud"} & set(data.get("tags", []))) or len(data.get("hostnames", [])) > 10
        for host in data.get("hostnames", [])[:25]:
            # On CDN/cloud edges hostnames are unrelated co-tenants: record them, do not pivot on them.
            res.pivot(T.DOMAIN, host, "hosted_domain", confidence=0.5 if shared_edge else 0.8, expand=not shared_edge)
        for cve in data.get("vulns", []):
            res.pivot(T.CVE, cve, "has_vuln", confidence=0.6, note="version-based match: confirm on the host")
        tags = set(data.get("tags", []))
        if "tor" in tags:
            res.attr("is_tor_exit", True)
        if "vpn" in tags or "proxy" in tags:
            res.attr("is_proxy", True)
        if "cdn" in tags:
            res.attr("is_cdn", True)
        if "cloud" in tags:
            res.attr("is_hosting", True)
        if ports:
            res.finding(
                f"{len(ports)} open port(s): {', '.join(map(str, ports[:15]))}",
                "info",
                "Observed by Shodan scanners (may be days old).",
                data={"ports": ports},
                tags=["exposure"],
                references=[f"https://www.shodan.io/host/{entity.value}"],
            )
        risky = {p: RISKY_PORTS[p] for p in ports if p in RISKY_PORTS}
        if risky:
            res.finding(
                f"Sensitive services exposed to the internet: {', '.join(f'{p}/{n}' for p, n in risky.items())}",
                "medium",
                "Databases, remote desktops and admin interfaces should not be reachable from the internet.",
                data={"risky_ports": risky},
                tags=["exposure", "misconfiguration"],
            )
        vulns = data.get("vulns", [])
        if vulns:
            res.finding(
                f"{len(vulns)} CVE(s) associated with exposed software",
                "high" if len(vulns) >= 5 else "medium",
                "Shodan matches CVEs from service versions/CPEs; confirm before acting.",
                data={"cves": vulns[:50]},
                tags=["vulnerable"],
                confidence=0.6,
            )
        if tags & {"malware", "c2", "compromised"}:
            res.finding(f"Shodan tags: {', '.join(sorted(tags))}", "high", tags=["malicious", "c2"] if "c2" in tags else ["malicious"])
        res.link("Shodan host page", f"https://www.shodan.io/host/{entity.value}")
        return res
