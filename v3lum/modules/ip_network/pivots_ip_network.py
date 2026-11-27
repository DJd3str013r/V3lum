"""pivots_ip_network: IP & ASN tools, manual pivot links only (P057, batch p2-G14-1).

Disclosure ``none``: the module only builds URLs (``ctx.http`` refuses every request); V3LUM never requests
these pages or any API behind them (P057 cond 1). The pack is ``v3lum/data/pivot_links/ip_network.json``:

* its ``links`` (bgp.he.net IP and AS pages, IPinfo IP and ASN pages, Scamalytics, CIDR Report, Myip.ms; cond 8)
  are core pack links, rendered by the engine and by ``v3lum links``. Tor ExoneraTor is ``tor_relays:exonerator``
  (same template, referenced in ``x_served_by``);
* the ``x_module_links`` are rendered here: the bgp.he.net prefix page (the vetted ``{cidrp}`` encoder keeps the
  literal '/' the site needs), Criminal IP and the FOFA ip/icon_hash searches. FOFA uses the vetted ``{b64q}``
  placeholder: ``links.b64`` over the fixed expression of the entry (cond 11); Criminal IP and FOFA carry the
  foreign-provider badge and ``x_max_tlp`` green, so they are not emitted at TLP:AMBER and above (cond 10).

Cond 9 (redteam_lead): no module link renders for private, loopback, link-local, CGNAT, ULA, multicast,
documentation or reserved addresses, overlapping CIDRs, private/reserved ASNs or internal names
(``pivot_gated_links.public_value_problem``, one unit test per range). The engine never attaches pack links to
noise entities (private, loopback, link-local, ULA, reserved and documentation addresses); the core pack links
still render for a CGNAT address and for any value typed into ``v3lum links``: recorded in
docs/backlog/p2-G14-1.md with the core request (a public-value filter in ``links.render``; every core link of the
pack carries ``x_public_only: true`` for it).

Cond 5 tiers come from the provider registry: hurricane_electric, ipinfo, torproject, cidr_report trusted;
criminalip and scamalytics community; myipms unknown (IP values only, 'unknown operator' badge, last). The fofa
provider (another batch's fragment) is recorded as unknown: FOFA links carry the 'unknown operator' badge until
the registry reviewer confirms the community tier of cond 5.
"""

from __future__ import annotations

from typing import Any

from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import ModuleResult, Opsec
from v3lum.core.module import Module, register
from v3lum.modules.utility import pivot_gated_links as pg

PACK = "ip_network"


@register
class PivotsIpNetwork(Module):
    name = "pivots_ip_network"
    title = "IP & ASN tools (manual pivot links)"
    description = (
        "Manual pivot links for IPs, prefixes, ASNs and favicon hashes (bgp.he.net, IPinfo, Scamalytics, CIDR Report, "
        "Myip.ms: pack ip_network) plus the bgp.he.net prefix page, Criminal IP and FOFA (vetted base64 query), never "
        "for private or reserved values. V3LUM never fetches them."
    )
    category = "ip_network"
    accepts = {T.IPV4, T.CIDR, T.FAVICON_HASH}
    produces = frozenset()
    reference = "https://bgp.he.net/"
    tags = {"offline", "pack"}
    notice = (
        "Manual links only (never fetched); no link for private, CGNAT, loopback, link-local, ULA or reserved values. "
        "FOFA (CN) and Criminal IP (KR) are foreign providers: queries are logged abroad - never paste internal host "
        "names; they are listed only up to TLP:GREEN."
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
