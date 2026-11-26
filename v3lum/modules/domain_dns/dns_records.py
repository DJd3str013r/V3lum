"""Core DNS records of a domain (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) with the resolver AD flag.

Reference implementation (module contract v2) for DoH-only modules:

* declares ``provider='core_doh'``, ``sources=('core_doh.resolvers',)``, ``hosts=()`` and
  ``disclosure='third_party'``: the value reaches the DoH resolver operator, never the target;
* uses only ``ctx.dns`` (not counted in ``max_requests``, hence ``max_requests = 0``);
* rule 5: answers that could not be verified (SERVFAIL, REFUSED, timeouts, transport errors) never
  become absence claims. Negative findings ('No web-facing address') need NOERROR answers for
  A, AAAA and CNAME, and 'does not resolve' needs an NXDOMAIN confirmed by a second resolver;
* the AD flag is reported as 'validated by resolver', never as proof of DNSSEC.
"""

from __future__ import annotations

from typing import Any

from v3lum.core import psl
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
WEB_TYPES = ("A", "AAAA", "CNAME")


@register
class DnsRecords(Module):
    name = "dns_records"
    title = "DNS records"
    description = "A/AAAA/CNAME/MX/NS/TXT/SOA/CAA records via the core DNS-over-HTTPS resolvers, resolver AD flag, parent domain."
    category = "domain_dns"
    accepts = {T.DOMAIN}
    produces = {T.IPV4, T.IPV6, T.DOMAIN}
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "core_doh"
    sources = ("core_doh.resolvers",)
    hosts = ()
    access_model = "free_noauth_unlimited"
    max_requests = 0  # DoH only: ctx.dns is not counted
    expected_latency = 1.5
    reference = "https://developers.google.com/speed/public-dns/docs/doh/json"
    tags = {"free", "core"}
    cache_ttl = 3600

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        dom = entity.value
        answers = {rt: ctx.dns.query(dom, rt) for rt in RECORD_TYPES}
        raw: dict[str, Any] = {
            rt: {
                "status": a.status,
                "records": a.records,
                "validated_by_resolver": a.authenticated,
                "error": a.error,
                "resolver": getattr(a, "resolver", ""),
            }
            for rt, a in answers.items()
        }
        res.raw = raw
        ok = {rt: a for rt, a in answers.items() if a.ok}

        if not ok:
            if any(a.nxdomain for a in answers.values()):
                confirmed = ctx.dns.confirm_nxdomain(dom)
                raw["nxdomain_confirmed"] = confirmed
                if confirmed is True:
                    res.attr("valid", False)
                    res.finding(
                        "Domain does not resolve (NXDOMAIN)",
                        "info",
                        "The DNS answered NXDOMAIN for this name and a second resolver confirmed it.",
                        confidence="confirmed",
                        criterion="NXDOMAIN (Status 3) confirmed by a second resolver",
                        tags=["info"],
                        source="core_doh.resolvers",
                    )
                    return res
                return res.mark("error", "NXDOMAIN not confirmed by a second resolver: could not verify")
            errors = sorted({a.error or a.status for a in answers.values()})
            return res.mark("error", "DNS could not verify the records: " + "; ".join(errors))
        # Types without a NOERROR answer (SERVFAIL, timeouts, or an NXDOMAIN contradicting the
        # other answers) are 'could not verify': they never feed an absence claim below.
        unverified = sorted(rt for rt in RECORD_TYPES if rt not in ok)
        if unverified:
            raw["could_not_verify"] = unverified
            res.error = "could not verify: " + ", ".join(f"{rt} ({answers[rt].status})" for rt in unverified)

        def records(rt: str) -> list[str]:
            return ok[rt].records if rt in ok else []

        a_recs = [r for r in records("A") if r.count(".") == 3]
        aaaa = [r for r in records("AAAA") if ":" in r]
        mx_hosts = [r.split()[-1] for r in records("MX") if r.strip()]
        txt = records("TXT")
        res.attr("a_records", a_recs)
        res.attr("aaaa_records", aaaa)
        res.attr("mx", mx_hosts)
        res.attr("nameservers", records("NS"))
        res.attr("txt", txt)
        res.attr("dnssec", any(a.authenticated for a in ok.values()))  # AD flag: validated by resolver, not proof
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if spf:
            res.attr("spf", spf[0])
        res.attr("caa", records("CAA"))
        if records("SOA"):
            res.attr("soa", records("SOA")[0])

        for ip in a_recs:
            res.pivot(T.IPV4, ip, "resolves_to")
        for ip in aaaa:
            res.pivot(T.IPV6, ip, "resolves_to")
        for target in records("CNAME"):
            res.pivot(T.DOMAIN, target, "cname_to")
        for mx in mx_hosts:
            if mx != ".":
                res.pivot(T.DOMAIN, mx, "mx_host", expand=False)
        for ns in records("NS"):
            res.pivot(T.DOMAIN, ns, "nameserver", expand=False)
        parent = psl.registrable_domain(dom)
        if parent and parent != dom:
            res.pivot(T.DOMAIN, parent, "parent_domain")

        web_answered = all(rt in ok for rt in WEB_TYPES)
        if web_answered and not a_recs and not aaaa and not records("CNAME"):
            res.finding(
                "No web-facing address (no A/AAAA/CNAME)",
                "info",
                "The name exists but does not point to a host.",
                criterion="NOERROR answers without A, AAAA or CNAME records",
                tags=["info"],
                source="core_doh.resolvers",
            )
        if mx_hosts == ["."]:
            res.finding(
                "Null MX: domain explicitly refuses email",
                "info",
                "RFC 7505 null MX record.",
                confidence="confirmed",
                criterion="MX answer is the RFC 7505 null MX ('0 .')",
                tags=["info"],
                source="core_doh.resolvers",
            )
        return res
