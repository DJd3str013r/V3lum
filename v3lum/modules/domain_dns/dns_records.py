"""Core DNS records of a domain (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) with DNSSEC flag.

Reference implementation for module authors: uses only ctx.dns, records vocabulary
attributes, pivots on IPs/hosts and emits findings with semantic tags.
"""

from __future__ import annotations

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult
from v3lum.core.module import Module, register


@register
class DnsRecords(Module):
    name = "dns_records"
    title = "DNS records"
    description = "A/AAAA/CNAME/MX/NS/TXT/SOA/CAA records via DNS-over-HTTPS, DNSSEC status, parent domain."
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.IPV4, T.IPV6, T.DOMAIN}
    hosts = ("dns.google", "cloudflare-dns.com")
    reference = "https://developers.google.com/speed/public-dns/docs/doh/json"
    tags = {"free", "core"}
    cache_ttl = 3600

    def run(self, entity: Entity, ctx: object) -> ModuleResult:
        res = self.result(entity)
        dom = entity.value
        raw: dict[str, object] = {}
        answers = {rt: ctx.dns.query(dom, rt) for rt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")}
        for rt, ans in answers.items():
            raw[rt] = {"status": ans.status, "records": ans.records, "ad": ans.authenticated, "error": ans.error}

        if all(a.nxdomain for a in answers.values()):
            res.attr("valid", False)
            res.finding("Domain does not resolve (NXDOMAIN)", "info", "No DNS records exist for this name.", tags=["info"])
            res.raw = raw
            return res
        if all(not a.ok for a in answers.values()):
            res.raw = raw
            return res.mark("error", "; ".join({a.error for a in answers.values() if a.error}) or "DNS failure")

        a_recs = [r for r in answers["A"].records if r.count(".") == 3]
        aaaa = [r for r in answers["AAAA"].records if ":" in r]
        mx_hosts = [r.split()[-1] for r in answers["MX"].records if r.strip()]
        ns_hosts = answers["NS"].records
        txt = answers["TXT"].records
        res.attr("a_records", a_recs)
        res.attr("aaaa_records", aaaa)
        res.attr("mx", mx_hosts)
        res.attr("nameservers", ns_hosts)
        res.attr("txt", txt)
        res.attr("dnssec", any(a.authenticated for a in answers.values()))
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if spf:
            res.attr("spf", spf[0])
        if answers["CAA"].records:
            res.attr("caa", answers["CAA"].records)
        if answers["SOA"].records:
            res.attr("soa", answers["SOA"].records[0])

        for ip in a_recs:
            res.pivot(T.IPV4, ip, "resolves_to")
        for ip in aaaa:
            res.pivot(T.IPV6, ip, "resolves_to")
        for target in answers["CNAME"].records:
            res.pivot(T.DOMAIN, target, "cname_to")
        for mx in mx_hosts:
            if mx != ".":
                res.pivot(T.DOMAIN, mx, "mx_host", expand=False)
        for ns in ns_hosts:
            res.pivot(T.DOMAIN, ns, "nameserver", expand=False)
        parent = psl.registrable_domain(dom)
        if parent and parent != dom:
            res.pivot(T.DOMAIN, parent, "parent_domain")

        if not a_recs and not aaaa and not answers["CNAME"].records:
            res.finding("No web-facing address (no A/AAAA/CNAME)", "info", "The name exists but does not point to a host.", tags=["info"])
        if mx_hosts == ["."]:
            res.finding("Null MX: domain explicitly refuses email", "info", "RFC 7505 null MX record.", tags=["info"])
        res.raw = raw
        return res
