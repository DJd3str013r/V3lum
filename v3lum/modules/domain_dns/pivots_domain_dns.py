"""pivots_domain_dns: domain & DNS tools, manual pivot links only (P026, batch p2-G14-1).

Disclosure ``none``: the module only builds URLs (``ctx.http`` refuses every request); V3LUM never requests
these pages or any API behind them (P026 cond 1). The pack is ``v3lum/data/pivot_links/domain_dns.json``:

* its ``links`` (DNSViz, Whoxy, host.io, MXToolbox spf:/dmarc:/mx:, dmarcian, CompleteDNS, DomainTools reverse
  IP and WHOIS, intoDNS, Verisign DNSSEC Debugger, who.is, whois.com; cond 8) are core pack links, rendered by
  the engine for seeds and first-hop entities and by ``v3lum links`` (A2 and P311 rendering, cond 2). The crt.sh
  HTML search is ``ct_rdap_lookups:crtsh_domain`` (same template; the pack references it in ``x_served_by``);
* the crt.sh certificate lookup by SHA-256 is an ``x_module_links`` entry rendered here, because the core link
  model cannot restrict a cert_fingerprint template to 64-hex values (cond 9): SHA-1 and other forms get no link
  from this pack. When a core pack already lists the same URL for the value, nothing is emitted twice (EMPTY).

Final conditions: cond 3 (CI render with sample and hostile values) and cond 4-5 (provider tiers) are covered by
tests/modules/test_p2_g14_1.py and the batch's provider fragments; cond 6 is the pack's file order (crt.sh,
DNSViz, Whoxy, host.io, MXToolbox, dmarcian, then CompleteDNS, DomainTools, intoDNS, Verisign, who.is,
whois.com); cond 7 is ``pivot_gated_links.recheck_report``; cond 10 flags intoDNS, MXToolbox, dmarcian and the
Verisign debugger touches_target (the renderers defang them, show the warning and hide them for hostile entities
unless expanded) and the DNSViz label warns about 'Analyze'; cond 11 keeps whois.domaintools.com antibot,
unverified and last in its group, and publishes=false everywhere (P311 lint).
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_gated_links as pg

PACK = "domain_dns"


@register
class PivotsDomainDns(Module):
    name = "pivots_domain_dns"
    title = "Domain & DNS tools (manual pivot links)"
    description = (
        "Manual pivot links for domains (crt.sh, DNSViz, Whoxy, host.io, MXToolbox, dmarcian, CompleteDNS, "
        "DomainTools, intoDNS, Verisign DNSSEC Debugger, who.is, whois.com: pack domain_dns) and the crt.sh "
        "certificate lookup for SHA-256 fingerprints. V3LUM never fetches them."
    )
    category = "domain_dns"
    accepts = {T.CERT_FP}
    produces = frozenset()
    reference = "https://crt.sh/"
    tags = {"offline", "pack", "cert_derived"}
    notice = (
        "Manual links only (never fetched). intoDNS, MXToolbox, dmarcian and the Verisign debugger query the target's "
        "DNS live when opened; DNSViz's 'Analyze' button runs and publishes a fresh analysis. At TLP:AMBER and above "
        "links are non-clickable text with 'opening sends <value> to <host>'; at RED only `v3lum links` lists them."
    )
    terms = "open"
    opsec = Opsec.PASSIVE
    disclosure = "none"  # the module only builds URLs
    hosts = ()
    access_model = "offline"
    max_requests = 0
    expected_latency = 0.01
    timeout = 10.0
    default_enabled = True

    def run(self, entity: Entity, ctx: Any) -> ModuleResult:
        return pg.run_links(self, entity, ctx, PACK)
