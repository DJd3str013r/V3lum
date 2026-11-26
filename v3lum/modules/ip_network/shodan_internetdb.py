"""Shodan InternetDB: open ports, hostnames, CPEs, tags and version-inferred CVEs for an IP (no key).

Reference implementation (module contract v2) for keyless HTTP API modules:

* every host and feed is in the provider registry (``provider='shodan'``,
  ``sources=('shodan.internetdb',)``); ``terms`` is the most restrictive source class:
  'noncommercial' (A1 initial class) - off under the corporate profile until licence-cleared;
* ``absent_statuses={404}``: InternetDB answers 404 'No information available' for IPs it never
  saw, so ``ctx.http.get_json`` returns None (a documented, meaningful absence, P328 cond 5);
  429, challenge pages and errors inside 200 bodies raise and become could-not-verify statuses;
* findings carry ``source`` and a criterion; CVEs are version-inferred, hence 'possible';
* the answer is untrusted data: a body that is not a JSON object is 'could not verify' (never an
  empty result) and every field is type-checked before use.
"""

from __future__ import annotations

import re
from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

SOURCE = "shodan.internetdb"
API = "https://internetdb.shodan.io/{ip}"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API (unauthenticated)", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 5601: "Kibana", 8086: "InfluxDB", 9000: "admin panel / PHP-FPM",
}
BAD_TAGS = {"malware", "c2", "compromised"}


@register
class ShodanInternetDB(Module):
    name = "shodan_internetdb"
    title = "Shodan InternetDB"
    description = "Open ports, hostnames, CPEs, tags and version-inferred CVEs for an IP from Shodan's free InternetDB."
    category = "ip_network"
    accepts = {T.IPV4, T.IPV6}
    produces = {T.DOMAIN, T.CVE}
    terms = "noncommercial"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "shodan"
    sources = (SOURCE,)
    hosts = ("internetdb.shodan.io",)
    access_model = "free_noauth_limited"
    absent_statuses = frozenset({404})
    max_requests = 1
    expected_latency = 1.0
    manual_link = "core_reference:shodan_host"
    reference = "https://internetdb.shodan.io/docs"
    notice = "Shodan InternetDB terms are noncommercial: off under the corporate profile until licence-cleared."
    tags = {"free", "core"}
    cache_ttl = 86400

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return is_public_ip(entity.value)

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = entity.value
        data = ctx.http.get_json(API.format(ip=ip), source=SOURCE)
        if data is None:  # 404: Shodan has no record of this IP (documented absence)
            return res.mark("empty")
        if not isinstance(data, dict):  # never read an unexpected answer as 'nothing found' (rule 5)
            return res.mark("error", f"unexpected InternetDB answer ({type(data).__name__}, not a JSON object): could not verify")
        res.raw = data
        ports = sorted({int(p) for p in _strings_or_ints(data, "ports") if str(p).isdigit() and 0 < int(p) < 65536})
        hostnames = _strings(data, "hostnames")
        vulns = sorted({v.strip().upper() for v in _strings(data, "vulns") if CVE_RE.match(v.strip().upper())})
        cpes = [c for c in _strings(data, "cpes") if c.startswith("cpe:")]
        tags = set(_strings(data, "tags"))
        res.attr("open_ports", ports)
        res.attr("hostnames", hostnames)
        res.attr("cpes", cpes)
        res.attr("tags", sorted(tags))
        res.attr("vulns", vulns)
        shared_edge = bool({"cdn", "cloud"} & tags) or len(hostnames) > 10
        for host in hostnames[:25]:
            # On CDN/cloud edges hostnames are unrelated co-tenants: record them, do not pivot on them.
            res.pivot(T.DOMAIN, host, "hosted_domain", confidence=0.5 if shared_edge else 0.8, expand=not shared_edge)
        for cve in vulns:
            res.pivot(T.CVE, cve, "has_vuln", confidence="possible", note="version-inferred: confirm on the host")
        if "tor" in tags:
            res.attr("is_tor_exit", True)
        if "vpn" in tags or "proxy" in tags:
            res.attr("is_proxy", True)
        if "cdn" in tags:
            res.attr("is_cdn", True)
        if "cloud" in tags:
            res.attr("is_hosting", True)
        reference = f"https://www.shodan.io/host/{ip}"
        if ports:
            res.finding(
                "Open ports observed by Shodan",
                "info",
                f"{len(ports)} open port(s): {', '.join(map(str, ports[:15]))}. Observed by Shodan scanners (may be days old).",
                data={"ports": ports},
                tags=["exposure"],
                references=[reference],
                source=SOURCE,
            )
        risky = {p: RISKY_PORTS[p] for p in ports if p in RISKY_PORTS}
        if risky:
            res.finding(
                "Sensitive services exposed to the internet",
                "medium",
                "Databases, remote desktops and admin interfaces should not be reachable from the internet: "
                + ", ".join(f"{p}/{n}" for p, n in risky.items()),
                confidence="probable",
                criterion="port listed as open by Shodan scan data (may be days old): confirm current exposure",
                data={"risky_ports": risky},
                tags=["exposure", "misconfiguration"],
                references=[reference],
                source=SOURCE,
            )
        if vulns:
            res.finding(
                "CVE(s) associated with exposed software (version-inferred)",
                "medium",
                f"{len(vulns)} CVE(s) matched by Shodan from service versions/CPEs.",
                confidence="possible",
                criterion="version-inferred, distro backports not considered: confirm on the host",
                data={"cves": vulns[:50], "count": len(vulns)},
                tags=["vulnerable", "version_inferred"],
                references=[reference],
                source=SOURCE,
            )
        bad = sorted(tags & BAD_TAGS)
        if bad:
            res.finding(
                "Shodan classifies the host as malicious",
                "high",
                f"Shodan tags: {', '.join(sorted(tags))}.",
                confidence="probable",
                criterion=f"Shodan scanner tag(s) {', '.join(bad)} on the host",
                tags=["malicious", "c2"] if "c2" in tags else ["malicious"],
                references=[reference],
                source=SOURCE,
            )
        res.link("Shodan host page", reference)
        return res


def _strings(data: dict[str, Any], key: str) -> list[str]:
    """String items of the list field ``key`` (missing, null or non-list fields give [])."""
    value = data.get(key)
    return [v for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


def _strings_or_ints(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    return [v for v in value if isinstance(v, (str, int)) and not isinstance(v, bool)] if isinstance(value, list) else []
