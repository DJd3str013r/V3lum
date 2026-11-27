"""Opt-in protective-DNS resolvers (P020 cond 2): AdGuard (default 'ads' and family filters, JSON
DoH), OpenDNS (standard 'security' and FamilyShield 'family', RFC 8484) and CleanBrowsing (security and
family filters, RFC 8484) - same engine, signatures and severity ladder as ``protective_dns``.

AdGuard and OpenDNS stay terms 'unknown' until legal records their terms (never run in any profile
until then); CleanBrowsing's free filters are 'for parents, not organizations' (noncommercial) and run
only with a paid team account recorded as a licence (a licence_allow entry for its sources). The
policy gate hands the passing feeds in ``ctx.allowed_sources``; the engine reports the others.
OpenDNS FamilyShield (named by cond 4) needs doh.familyshield.opendns.com, registered with the OpenDNS
provider. Wire-format resolvers need dnspython (UNAVAILABLE 'package' per resolver without it).
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.domain_dns.protective_dns import TTL_CAP, ProtectiveRun, ResolverSpec, query_name

__all__ = ["EXTRA_RESOLVERS", "ProtectiveDnsExtra"]

EXTRA_RESOLVERS: tuple[ResolverSpec, ...] = (
    ResolverSpec("adguard_default", "AdGuard DNS (default)", "adguard.default", "https://dns.adguard-dns.com/resolve", "json", "ads"),
    ResolverSpec("adguard_family", "AdGuard DNS (family)", "adguard.family", "https://family.adguard-dns.com/resolve", "json", "family"),
    ResolverSpec("opendns", "OpenDNS", "opendns.standard", "https://doh.opendns.com/dns-query", "wire", "security"),
    ResolverSpec("opendns_familyshield", "OpenDNS FamilyShield", "opendns.familyshield",
                 "https://doh.familyshield.opendns.com/dns-query", "wire", "family"),
    ResolverSpec("cleanbrowsing_security", "CleanBrowsing (security)", "cleanbrowsing.security_filter",
                 "https://doh.cleanbrowsing.org/doh/security-filter/dns-query", "wire", "security"),
    ResolverSpec("cleanbrowsing_family", "CleanBrowsing (family)", "cleanbrowsing.family_filter",
                 "https://doh.cleanbrowsing.org/doh/family-filter/dns-query", "wire", "family"),
)


@register
class ProtectiveDnsExtra(Module):
    name = "protective_dns_extra"
    title = "Protective-DNS block check, extra resolvers (AdGuard, OpenDNS, CleanBrowsing)"
    description = (
        "Opt-in protective-DNS check against AdGuard (ads/family), OpenDNS (standard/FamilyShield) and CleanBrowsing "
        "(security/family) with the same signatures, reference rule and severity ladder as protective_dns."
    )
    category = "domain_dns"
    accepts = {T.DOMAIN, T.URL}
    produces = set()
    tags = {"reputation", "free"}
    reference = "https://adguard-dns.io/en/public-dns.html"
    terms = "unknown"  # AdGuard and OpenDNS: 'unknown' until legal records their terms (P020 cond 2)
    opsec = Opsec.PASSIVE
    disclosure = "third_party"
    provider = "opendns"
    sources = tuple(spec.source for spec in EXTRA_RESOLVERS)
    hosts = ("dns.adguard-dns.com", "family.adguard-dns.com", "doh.opendns.com", "doh.familyshield.opendns.com", "doh.cleanbrowsing.org")
    access_model = "free_noauth_unlimited"
    max_requests = 6  # one A query per resolver per name (P020 cond 3)
    expected_latency = 1.0
    timeout = 20.0
    cache_ttl = TTL_CAP
    default_enabled = False  # opt-in module (P020 cond 2); terms unknown (A3)
    notice = (
        "AdGuard and OpenDNS run only once legal records their terms; CleanBrowsing's free filters are not for organisations "
        "(noncommercial): it runs only with a paid team account recorded as a licence. Family/ads blocks are content "
        "categories, never maliciousness."
    )

    def applies(self, entity: Entity, ctx: Any) -> bool:
        return query_name(entity) is not None

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        res = self.result(entity)
        name = query_name(entity)
        if name is None:
            return res.mark("skipped", "no DNS name to check (IP-literal URL or invalid host)", reason_code="not_applicable")
        return ProtectiveRun(self, res, ctx, name, EXTRA_RESOLVERS).execute()
