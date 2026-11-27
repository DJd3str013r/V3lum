"""Shodan InternetDB: open ports, hostnames, CPEs, tags and version-inferred CVEs for an IP (no key).

Reference implementation (module contract v2) for keyless HTTP API modules, upgraded by batch
p1-G02-2 (P043, final conditions):

* c1 - ``terms='noncommercial'`` (A1 initial class) - the registry source ``shodan.internetdb`` is
  noncommercial and ``terms`` is the most restrictive source class.
* c2-c4 - off under the corporate profile until licence-cleared: the policy gate (POL-04) skips it
  (SKIPPED reason_code 'licence') unless a licence_allow entry records Shodan's written permission
  or a company plan covering this use; the Shodan host page is the manual link and the notice
  points to ``shodan_api`` (P039) with the company key. Nothing ever replaces it automatically
  (no active port scan fallback).
* c5 - ``absent_statuses={404}``: the documented 404 ``{"detail": "No information available"}``
  reads 'not seen by Shodan scanners' (info), never 'no open ports'. Any other 404 body (the same
  status also answers malformed paths) is 'could not verify'.
* c6 - InternetDB has no observation timestamps: every port and CVE line carries 'last seen
  unknown (data may be weeks old)' (the Last-Modified header is a CDN cache date, never shown as
  a scan date); risky-port findings are at most MEDIUM.
* c7 - CVEs are version-inferred (P291): one finding per host ('N CVEs by version match, KEV: k'),
  POSSIBLE, CVE pivots at confidence 0.5, MEDIUM (HIGH only when a CVE is known to be in CISA KEV),
  labelled 'version-inferred, backports not considered', never CRITICAL from InternetDB alone.
* c8 - tags (cdn, cloud, self-signed, eol...) map to attributes; hostnames of a CDN/shared IP
  (P034 noise kinds, or more than 10 names) are co-tenants: listed with ``expand=False``.

The answer is untrusted data: a body that is not a JSON object is 'could not verify' (never an
empty result) and every field is type-checked before use.
"""

from __future__ import annotations

import json
import re
from typing import Any

from v3lum.core import noise
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.core.noise import is_public_ip

SOURCE = "shodan.internetdb"
API = "https://internetdb.shodan.io/{ip}"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
NOT_SEEN = "not seen by Shodan scanners"
LAST_SEEN = "last seen unknown (data may be weeks old)"
CVE_LABEL = "version-inferred, backports not considered"
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 135: "MS-RPC", 139: "NetBIOS", 161: "SNMP", 445: "SMB",
    502: "Modbus", 623: "IPMI", 873: "rsync", 1433: "MSSQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS",
    2375: "Docker API (unauthenticated)", 2379: "etcd", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5601: "Kibana", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API", 8086: "InfluxDB",
    9000: "admin panel / PHP-FPM", 9042: "Cassandra", 9200: "Elasticsearch", 10250: "kubelet", 11211: "Memcached",
    20000: "DNP3", 27017: "MongoDB", 47808: "BACnet",
}
BAD_TAGS = {"malware", "c2", "compromised"}
#: InternetDB tag -> boolean attribute (P043 c8); every tag is also kept in attribute 'tags'.
TAG_ATTRIBUTES = {
    "cdn": "is_cdn", "cloud": "is_hosting", "vpn": "is_vpn", "proxy": "is_proxy", "tor": "is_tor_relay",
    "self-signed": "tls_self_signed", "eol-product": "eol_software", "eol-os": "eol_software", "honeypot": "is_honeypot",
    "ics": "is_ics", "scanner": "is_scanner",
}
#: Noise kinds (P034 / core noise lists) whose addresses are shared: hostnames there are co-tenants.
SHARED_KINDS = {"cdn", "cloud", "hosting", "saas", "resolver"}
MAX_EXPANDED_HOSTNAMES = 10


def kev_ids(ctx: Any) -> frozenset[str] | None:
    """CVE ids known to be in CISA KEV, or None when this module cannot tell (no KEV source is
    wired here yet: the KEV cap is applied by the P291 rules on the CVE pivots)."""
    return None


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
    min_interval = 1.0
    manual_link = "core_reference:shodan_host"
    reference = "https://internetdb.shodan.io/docs"
    notice = (
        "Shodan InternetDB terms are noncommercial: off under the corporate profile until licence-cleared "
        "(skipped: licence (Shodan non-commercial terms)) - a licence_allow entry recording Shodan's written "
        "permission or a company Shodan plan clears it; a licensed Shodan API key enables shodan_api (P039). "
        "Never replaced by an active port scan. InternetDB data carries no scan date: last seen unknown (data may be "
        "weeks old)."
    )
    tags = {"free", "core"}
    cache_ttl = 86400

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return is_public_ip(entity.value)  # private/reserved IPs: SKIPPED not_applicable, never sent

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        ip = entity.value
        reference = f"https://www.shodan.io/host/{ip}"
        resp = ctx.http.get(API.format(ip=ip), source=SOURCE, headers={"Accept": "application/json"})
        if resp.status == 404:
            body = _json(resp.content)
            if isinstance(body, dict) and str(body.get("detail", "")).strip().lower() == "no information available":
                # P043 c5: documented absence - the IP was not seen, which says nothing about open ports
                res.raw = {"status": 404, "detail": "No information available"}
                res.attr("internetdb_status", NOT_SEEN)
                res.finding(
                    "Not seen by Shodan scanners",
                    "info",
                    "InternetDB has no record of this IP ('No information available'). This is not evidence that no ports "
                    "are open: Shodan may simply not have scanned it recently.",
                    data={"state": "not_seen"},
                    references=[reference],
                    source=SOURCE,
                )
                res.link("Shodan host page", reference)
                return res.mark("empty")  # a documented absence: the source answered, nothing was seen
            ctx.http.check(resp)  # challenge pages and other 404 bodies raise: could not verify
            return res.mark("error", "unexpected InternetDB 404 answer: could not verify")
        ctx.http.check(resp)  # 429, 403, challenges, 5xx and error-in-200 markers raise (rule 5)
        data = _json(resp.content)
        if not isinstance(data, dict):  # never read an unexpected answer as 'nothing found' (rule 5)
            return res.mark("error", f"unexpected InternetDB answer ({type(data).__name__}, not a JSON object): could not verify")
        if "ip" not in data and "detail" in data:
            return res.mark("error", f"InternetDB answered {str(data.get('detail'))[:120]!r} without data: could not verify")
        res.raw = data
        ports = sorted({int(p) for p in _strings_or_ints(data, "ports") if str(p).isdigit() and 0 < int(p) < 65536})
        hostnames = []
        for host in _strings(data, "hostnames"):
            host = host.strip().lower().rstrip(".")
            if host and host not in hostnames:
                hostnames.append(host)
        vulns = sorted({v.strip().upper() for v in _strings(data, "vulns") if CVE_RE.match(v.strip().upper())})
        cpes = [c for c in _strings(data, "cpes") if c.startswith("cpe:")]
        tags = {t.strip().lower() for t in _strings(data, "tags") if t.strip()}
        res.attr("internetdb_status", "seen")
        res.attr("open_ports", ports)
        res.attr("hostnames", hostnames)
        res.attr("cpes", cpes)
        res.attr("tags", sorted(tags))
        res.attr("vulns", vulns)
        for tag in sorted(tags):
            if tag in TAG_ATTRIBUTES:
                res.attr(TAG_ATTRIBUTES[tag], True)
        kinds = set(noise.noise_kinds(entity))
        shared = bool({"cdn", "cloud"} & tags) or bool(kinds & SHARED_KINDS) or len(hostnames) > MAX_EXPANDED_HOSTNAMES
        if shared:
            res.attr("shared_ip", True)
        for host in hostnames[:25]:
            # On CDN/cloud/shared edges hostnames are unrelated co-tenants: record them, never expand them.
            res.pivot(
                T.DOMAIN, host, "hosted_domain", confidence=0.5 if shared else 0.8, expand=not shared,
                note="co-tenant of a shared/CDN IP, not the target" if shared else "",
            )
        if ports:
            res.finding(
                "Open ports observed by Shodan",
                "info",
                f"{len(ports)} open port(s): {', '.join(f'{p} ({LAST_SEEN})' for p in ports[:15])}.",
                data={"ports": ports, "last_seen": LAST_SEEN},
                tags=["exposure"],
                references=[reference],
                source=SOURCE,
            )
        risky = {p: RISKY_PORTS[p] for p in ports if p in RISKY_PORTS}
        if risky:
            res.finding(
                "Sensitive services exposed to the internet",
                "medium",  # P043 c6: at most MEDIUM from InternetDB data
                "Databases, remote desktops and admin interfaces should not be reachable from the internet: "
                + ", ".join(f"{p}/{n} ({LAST_SEEN})" for p, n in risky.items()),
                confidence="probable",
                criterion=f"port listed as open by Shodan scan data, {LAST_SEEN}: confirm current exposure",
                data={"risky_ports": risky, "last_seen": LAST_SEEN},
                tags=["exposure", "misconfiguration"],
                references=[reference],
                source=SOURCE,
            )
        if vulns:
            known = kev_ids(ctx)
            in_kev = sorted(set(vulns) & known) if known is not None else []
            kev_text = str(len(in_kev)) if known is not None else "not checked here (CVE pivots go to the KEV/EPSS sources)"
            res.finding(
                "CVEs by version match (version-inferred)",
                "high" if in_kev else "medium",  # P043 c7 / P291: HIGH only with KEV, never CRITICAL from InternetDB alone
                f"{len(vulns)} CVEs by version match, KEV: {kev_text}. {CVE_LABEL}; {LAST_SEEN}. "
                f"CVEs: {', '.join(vulns[:20])}{' ...' if len(vulns) > 20 else ''}",
                confidence="possible",
                criterion=f"{CVE_LABEL}: Shodan matched service versions/CPEs; confirm on the host",
                data={"cves": vulns[:100], "count": len(vulns), "kev": in_kev, "kev_checked": known is not None, "last_seen": LAST_SEEN},
                tags=["vulnerable", "version_inferred"] + (["kev"] if in_kev else []),
                references=[reference],
                source=SOURCE,
            )
            for cve in vulns[:50]:
                res.pivot(T.CVE, cve, "has_vuln", confidence=0.5, note=f"{CVE_LABEL}: confirm on the host")
        bad = sorted(tags & BAD_TAGS)
        if bad:
            res.finding(
                "Shodan classifies the host as malicious",
                "high",
                f"Shodan tags: {', '.join(sorted(tags))} ({LAST_SEEN}).",
                confidence="probable",
                criterion=f"Shodan scanner tag(s) {', '.join(bad)} on the host",
                tags=["malicious", "c2"] if "c2" in tags else ["malicious"],
                references=[reference],
                source=SOURCE,
            )
        res.link("Shodan host page", reference)
        return res


def _json(content: bytes) -> Any:
    try:
        return json.loads(content.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None


def _strings(data: dict[str, Any], key: str) -> list[str]:
    """String items of the list field ``key`` (missing, null or non-list fields give [])."""
    value = data.get(key)
    return [v for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


def _strings_or_ints(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    return [v for v in value if isinstance(v, (str, int)) and not isinstance(v, bool)] if isinstance(value, list) else []
